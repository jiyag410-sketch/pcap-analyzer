"""
credential_utils.py
Shared, dependency-free helpers used by password_detector.py: Basic-Auth
decoding, JWT recognition, and weak/default/reused password classification.

Kept separate from password_detector.py so the pattern-matching module and
the "is this credential bad" heuristics can be unit-tested independently.
Nothing here touches packet parsing or PacketRecord.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Optional

# Common default/well-known-weak passwords (forensic triage list, not a
# cracking dictionary -- intentionally short and focused on "this should
# never appear in cleartext" values).
WEAK_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "12345678", "123456789", "qwerty", "admin",
    "welcome", "letmein", "changeme", "password1", "admin123", "root",
    "toor", "guest", "test", "abc123", "iloveyou", "monkey", "dragon",
    "1234", "12345", "111111", "000000", "default", "pass",
})

# Common default username/password pairs seen on embedded devices,
# routers, and default installs.
DEFAULT_CREDENTIAL_PAIRS: frozenset[tuple[str, str]] = frozenset({
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("root", "root"), ("root", "toor"), ("root", ""),
    ("guest", "guest"), ("user", "user"), ("admin", "1234"),
    ("admin", "12345"), ("admin", "admin123"),
})


def decode_basic_auth(b64_value: str) -> Optional[tuple[str, str]]:
    """
    Decodes an HTTP `Authorization: Basic <b64>` value into (username,
    password). Returns None if it isn't valid base64 or doesn't contain
    a ':' separator -- callers should fall back to storing the raw token.
    """
    try:
        decoded = base64.b64decode(b64_value + "===").decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return None
    if ":" not in decoded:
        return None
    user, _, pwd = decoded.partition(":")
    return user, pwd


def is_probable_jwt(value: str) -> bool:
    """
    Cheap structural check for a JSON Web Token: three dot-separated
    base64url segments, first segment starts with the standard `eyJ`
    header prefix. Not a signature/validity check -- just recognition.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return parts[0].startswith("eyJ") and all(parts)


def classify_password(password: str, username: Optional[str] = None) -> tuple[str, list[str]]:
    """
    Returns (severity, reasons) for an observed plaintext password.
    severity is one of CRITICAL / HIGH, matching SEVERITY_COLOR_MAP keys
    in design_system.py so findings can reuse the existing chip styling.
    """
    reasons: list[str] = []
    pwd_lower = password.lower()

    if username and (username.lower(), pwd_lower) in DEFAULT_CREDENTIAL_PAIRS:
        reasons.append("default credential pair")

    if pwd_lower in WEAK_PASSWORDS:
        reasons.append("common/weak password")

    if len(password) < 8:
        reasons.append("short password (<8 chars)")

    if password.isdigit():
        reasons.append("numeric-only password")

    severity = "CRITICAL" if reasons else "HIGH"
    if not reasons:
        reasons.append("plaintext password in transit")

    return severity, reasons


@dataclass
class ReuseTracker:
    """
    Tracks how many times each (kind, value) pair has been observed across
    a capture so password_detector.py can flag reused credentials without
    needing a second pass over the packet list.
    """
    _seen: dict[tuple[str, str], int] = field(default_factory=dict)

    def record(self, kind: str, value: str) -> int:
        key = (kind, value)
        self._seen[key] = self._seen.get(key, 0) + 1
        return self._seen[key]

    def is_reused(self, kind: str, value: str) -> bool:
        return self._seen.get((kind, value), 0) > 1
