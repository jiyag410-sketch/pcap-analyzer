"""
password_detector.py
Broader credential/secret detector, modeled on NetworkMiner's "Credentials"
tab. This is a NEW, additive module -- it does not replace or modify
detectors/plaintext_creds.py, which keeps running exactly as before and
still feeds the existing "Alerts" tab and Markdown report.

SCOPE NOTE
----------
Like detectors/plaintext_creds.py, this module reads PacketRecord.payload_snippet,
which pcap_parser.py currently truncates to the first 256 printable bytes of
each packet's raw payload. That truncation is existing, tested parsing
behavior and is intentionally left unmodified here (per project rules).
Practical effect: credentials that appear after byte 256 of a payload (e.g.
a password field deep inside a large multipart form) may be missed. This
mirrors the limitation already present in the existing detector -- it is
not a new regression.

PROTOCOLS / FIELDS COVERED
---------------------------
HTTP POST form fields & JSON/XML bodies, HTTP Basic Authentication,
Authorization headers (Basic/Bearer/other), Cookie/Set-Cookie headers,
JWTs, generic API keys, FTP USER/PASS, POP3 USER/PASS, IMAP LOGIN,
SMTP AUTH, Telnet-style "login:"/"password:" prompts, IRC NICK/PASS,
and URL query-string credentials. WebSocket frames are plaintext TCP
payloads at this layer, so they're covered by the same generic patterns.

Findings are deduplicated on (kind, value, src_ip, dst_ip) so retransmitted
packets carrying the same field don't flood the table -- `occurrences`
records how many times each finding was actually seen.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Optional

from credential_utils import ReuseTracker, classify_password, decode_basic_auth, is_probable_jwt
from models import PacketRecord

# ----------------------------------------------------------------------
# Field names the brief asks us to look for, used to build the generic
# "key=value" / "key": "value" style patterns below.
# ----------------------------------------------------------------------
_CRED_FIELD_NAMES = (
    "password", "passwd", "pwd", "pass",
    "username", "user", "login", "email",
    "credential", "secret", "token", "apikey", "api_key", "key",
    "auth", "authorization",
)
_FIELD_ALTERNATION = "|".join(_CRED_FIELD_NAMES)

# Patterns that make sense on any TCP/UDP payload regardless of port
# (HTTP can run on non-standard ports, JSON/XML bodies, JWTs, etc).
_GENERIC_PATTERNS: list[tuple[re.Pattern, str]] = [
    # HTTP form-encoded / query-string: field=value
    (re.compile(rf"(?i)\b({_FIELD_ALTERNATION})=([^&\s\"'<>]{{1,128}})"), "form_field"),
    # JSON body: "field": "value"
    (re.compile(rf'(?i)"({_FIELD_ALTERNATION})"\s*:\s*"([^"]{{1,128}})"'), "json_field"),
    # XML body: <field>value</field>
    (re.compile(rf"(?i)<({_FIELD_ALTERNATION})>([^<]{{1,128}})</\1>"), "xml_field"),
    # Multipart form: Content-Disposition: form-data; name="password"
    (re.compile(rf'(?i)name="({_FIELD_ALTERNATION})"'), "multipart_field_name"),

    # HTTP auth headers
    (re.compile(r"(?i)Authorization:\s*Basic\s+(\S+)"), "http_basic_auth"),
    (re.compile(r"(?i)Authorization:\s*Bearer\s+(\S+)"), "bearer_token"),

    # Cookies / sessions
    (re.compile(r"(?i)\bSet-Cookie:\s*([^;\r\n]{1,200})"), "set_cookie"),
    (re.compile(r"(?i)\bCookie:\s*([^\r\n]{1,200})"), "cookie"),
    (re.compile(r"(?i)\b(?:JSESSIONID|PHPSESSID|ASP\.NET_SessionId|session_id|sid)=([A-Za-z0-9\-_.]{6,64})"), "session_id"),

    # Generic long API-key-shaped tokens (e.g. sk_live_..., AKIA...; 32+
    # char blobs following an "apikey"/"key" style field are already
    # caught by _FIELD_ALTERNATION above -- this catches bare
    # high-entropy tokens with recognizable vendor prefixes).
    (re.compile(r"\b((?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,64})\b"), "api_key_prefixed"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id"),
]

# Protocol-specific patterns, only applied when the destination (or
# source) port matches that protocol's well-known port. This avoids the
# same "USER x" / "PASS x" line being triple-counted as FTP, POP3, and
# IRC just because those protocols share terse plaintext verbs.
_FTP_PORTS = {21}
_POP3_PORTS = {110, 995}
_IMAP_PORTS = {143, 993}
_SMTP_PORTS = {25, 587, 465}
_TELNET_PORTS = {23}
_IRC_PORTS = {194, 6667, 6668, 6669, 6697}

_PROTOCOL_PATTERNS: list[tuple[frozenset, re.Pattern, str]] = [
    (frozenset(_FTP_PORTS), re.compile(r"(?im)^USER\s+(\S+)"), "ftp_user"),
    (frozenset(_FTP_PORTS), re.compile(r"(?im)^PASS\s+(\S+)"), "ftp_pass"),

    (frozenset(_POP3_PORTS), re.compile(r"(?im)^USER\s+(\S+)\s*$"), "pop3_user"),
    (frozenset(_POP3_PORTS), re.compile(r"(?im)^PASS\s+(\S+)\s*$"), "pop3_pass"),

    (frozenset(_IMAP_PORTS), re.compile(r'(?im)^\S+\s+LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?'), "imap_login"),

    # SMTP AUTH (base64 payloads follow AUTH LOGIN/PLAIN -- we flag the
    # exchange itself; full decode of the multi-line challenge/response
    # is out of scope for a single-packet-snippet scanner)
    (frozenset(_SMTP_PORTS), re.compile(r"(?im)^AUTH\s+(LOGIN|PLAIN|CRAM-MD5)"), "smtp_auth"),

    (frozenset(_TELNET_PORTS), re.compile(r"(?i)\blogin:\s*(\S+)"), "telnet_login"),
    (frozenset(_TELNET_PORTS), re.compile(r"(?i)\bpassword:\s*(\S+)"), "telnet_password"),

    (frozenset(_IRC_PORTS), re.compile(r"(?im)^NICK\s+(\S+)"), "irc_nick"),
    (frozenset(_IRC_PORTS), re.compile(r"(?im)^PASS\s+(\S+)"), "irc_pass"),
]


@dataclass
class CredentialFinding:
    packet_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: Optional[int]
    protocol: str
    field_type: str          # kind, e.g. "form_field", "http_basic_auth", "ftp_pass"
    field_name: Optional[str]
    value: str
    severity: str = "MEDIUM"
    reasons: list[str] = field(default_factory=list)
    reused: bool = False
    occurrences: int = 1
    host: Optional[str] = None
    url: Optional[str] = None
    http_method: Optional[str] = None

    def summary(self) -> str:
        name = f" ({self.field_name})" if self.field_name else ""
        return (f"[{self.severity}] {self.field_type}{name} seen {self.src_ip} -> "
                f"{self.dst_ip}: {self.value}")


# Field types treated as "this is a password value" for weak/default/reuse
# scoring; everything else (usernames, tokens, cookies) gets a fixed
# severity band instead of password-strength heuristics.
_PASSWORD_LIKE = {"ftp_pass", "pop3_pass", "irc_pass", "telnet_password"}

_SEVERITY_BY_KIND = {
    "http_basic_auth": "HIGH",
    "bearer_token": "MEDIUM",
    "set_cookie": "LOW",
    "cookie": "LOW",
    "session_id": "MEDIUM",
    "ftp_user": "LOW",
    "ftp_pass": "HIGH",
    "pop3_user": "LOW",
    "pop3_pass": "HIGH",
    "imap_login": "HIGH",
    "smtp_auth": "MEDIUM",
    "telnet_login": "LOW",
    "telnet_password": "HIGH",
    "irc_nick": "LOW",
    "irc_pass": "HIGH",
    "api_key_prefixed": "HIGH",
    "aws_access_key_id": "CRITICAL",
    "multipart_field_name": "LOW",
}


def _severity_for(kind: str, field_name: Optional[str], value: str) -> tuple[str, list[str]]:
    if kind in _PASSWORD_LIKE:
        return classify_password(value)

    if kind in ("form_field", "json_field", "xml_field") and field_name:
        low = field_name.lower()
        if low in ("password", "passwd", "pwd", "pass"):
            return classify_password(value)
        if low in ("token", "apikey", "api_key", "key", "secret", "auth", "authorization"):
            return "HIGH", ["credential/secret-shaped field observed in cleartext"]
        return "LOW", ["identity field (username/login/email) observed in cleartext"]

    if is_probable_jwt(value):
        return "MEDIUM", ["JWT observed in cleartext"]

    return _SEVERITY_BY_KIND.get(kind, "MEDIUM"), ["credential-relevant data observed in cleartext"]


def detect_credentials(records: list[PacketRecord]) -> list[CredentialFinding]:
    """
    Scans every record's payload_snippet for credential-shaped content and
    returns a deduplicated, severity-scored list of CredentialFinding.
    Pure function -- does not mutate records, does not touch the network.
    """
    reuse = ReuseTracker()
    dedup: dict[tuple, CredentialFinding] = {}

    for r in records:
        if not r.payload_snippet:
            continue

        text = r.payload_snippet
        ports = {p for p in (r.src_port, r.dst_port) if p is not None}

        applicable_patterns: list[tuple[re.Pattern, str]] = list(_GENERIC_PATTERNS)
        for allowed_ports, pattern, kind in _PROTOCOL_PATTERNS:
            if ports & allowed_ports:
                applicable_patterns.append((pattern, kind))

        for pattern, kind in applicable_patterns:
            for m in pattern.finditer(text):
                groups = m.groups()

                if kind == "http_basic_auth":
                    decoded = decode_basic_auth(groups[0])
                    if decoded:
                        user, pwd = decoded
                        _emit(dedup, reuse, r, kind, "Authorization", f"{user}:{pwd}")
                    else:
                        _emit(dedup, reuse, r, kind, "Authorization", groups[0][:120])
                    continue

                if kind == "imap_login" and len(groups) == 2:
                    _emit(dedup, reuse, r, "imap_login", "user", groups[0])
                    _emit(dedup, reuse, r, "imap_login", "pass", groups[1])
                    continue

                if kind == "multipart_field_name":
                    # Just tells us a sensitive field is present in this
                    # multipart body; the value itself is on a following
                    # line that a 256-byte snippet often won't include.
                    _emit(dedup, reuse, r, kind, groups[0], "(field present in multipart body)")
                    continue

                field_name = groups[0] if len(groups) >= 2 else None
                value = groups[-1]
                _emit(dedup, reuse, r, kind, field_name, value)

    findings = list(dedup.values())
    findings.sort(key=lambda f: f.timestamp)
    return findings


def _emit(
    dedup: dict[tuple, CredentialFinding],
    reuse: ReuseTracker,
    r: PacketRecord,
    kind: str,
    field_name: Optional[str],
    value: str,
) -> None:
    value = value.strip()
    if not value:
        return

    key = (kind, field_name, value, r.src_ip, r.dst_ip)
    if key in dedup:
        dedup[key].occurrences += 1
        return

    count = reuse.record(kind, value)
    severity, reasons = _severity_for(kind, field_name, value)

    dst_port = r.dst_port
    dst_port_str = str(dst_port) if dst_port else None

    dedup[key] = CredentialFinding(
        packet_index=r.index,
        timestamp=r.timestamp,
        src_ip=r.src_ip or "?",
        dst_ip=r.dst_ip or "?",
        dst_port=dst_port,
        protocol=r.protocol,
        field_type=kind,
        field_name=field_name,
        value=value[:200],
        severity=severity,
        reasons=reasons,
        reused=count > 1,
        host=r.http_host,
        url=(f"{r.http_host}{r.http_path}" if r.http_host and r.http_path else None),
    )


def findings_to_dicts(findings: list[CredentialFinding]) -> list[dict]:
    """Flat dict representation used by the dashboard table and CSV export."""
    return [
        {
            "Timestamp": f.timestamp,
            "Severity": f.severity,
            "Type": f.field_type,
            "Field": f.field_name or "",
            "Value": f.value,
            "Source": f.src_ip,
            "Destination": f.dst_ip,
            "Port": f.dst_port or "",
            "Protocol": f.protocol,
            "Host": f.host or "",
            "URL": f.url or "",
            "Reused": f.reused,
            "Occurrences": f.occurrences,
            "Notes": "; ".join(f.reasons),
        }
        for f in findings
    ]
