"""
detectors/plaintext_creds.py
Scans raw packet payloads for patterns that look like credentials sent in
cleartext (HTTP form fields, FTP/Telnet auth commands, basic auth headers).
Wireshark can do this via "Follow Stream" but only one conversation at a
time, manually -- this scans the whole capture and surfaces every hit.
"""

from __future__ import annotations
from dataclasses import dataclass
import re

from models import PacketRecord

# Patterns are intentionally simple/greedy -- forensic triage favors recall
# over precision here; a human still reviews every hit.
_PATTERNS = [
    (re.compile(rb"(?i)(user(?:name)?)=([^&\s]{1,64})"), "form_username"),
    (re.compile(rb"(?i)(pass(?:word)?)=([^&\s]{1,64})"), "form_password"),
    (re.compile(rb"(?i)^USER (\S+)", re.MULTILINE), "ftp_user"),
    (re.compile(rb"(?i)^PASS (\S+)", re.MULTILINE), "ftp_pass"),
    (re.compile(rb"Authorization: Basic (\S+)"), "http_basic_auth"),
]


@dataclass
class CredAlert:
    packet_index: int
    timestamp: float
    src_ip: str
    dst_ip: str
    kind: str
    matched_text: str
    severity: str = "HIGH"

    def summary(self) -> str:
        return (f"Plaintext credential ({self.kind}) seen {self.src_ip} -> "
                f"{self.dst_ip}: {self.matched_text}")


def detect_plaintext_creds(records: list[PacketRecord]) -> list[CredAlert]:
    alerts: list[CredAlert] = []

    for r in records:
        if not r.payload_snippet:
            continue
        payload_bytes = r.payload_snippet.encode(errors="ignore")

        for pattern, kind in _PATTERNS:
            for m in pattern.finditer(payload_bytes):
                matched = m.group(0).decode(errors="ignore")
                alerts.append(CredAlert(
                    packet_index=r.index,
                    timestamp=r.timestamp,
                    src_ip=r.src_ip or "?",
                    dst_ip=r.dst_ip or "?",
                    kind=kind,
                    matched_text=matched[:120],
                ))

    return alerts
