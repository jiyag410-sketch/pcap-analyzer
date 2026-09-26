"""
report_integrity.py
Forensic-grade integrity support for exported PDF reports.

Deliberately does NOT embed a self-referential hash inside the PDF (a PDF
containing its own final hash is a contradiction -- writing the hash bytes
into the file changes the file, which changes the hash). Instead this
module implements the standard DFIR pattern:

    1. Finalize the PDF on disk.
    2. Hash the finished, unmodified file (SHA-256).
    3. Write a *detached* sidecar file (`<report>.pdf.sha256`) containing
       that hash plus report metadata.
    4. The PDF itself only ever claims "see the accompanying .sha256 file"
       -- it never asserts its own hash.

verify_report_integrity() re-hashes the PDF and compares it against the
sidecar to confirm the report hasn't been altered since it was generated.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

PathLike = Union[str, "Path"]


def new_report_id() -> str:
    """Generates a fresh UUID4 report identifier."""
    return str(uuid.uuid4())


def _sha256_of_file(path: PathLike) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


@dataclass
class IntegrityRecord:
    """Everything written into (and read back from) a `.sha256` sidecar file."""
    pdf_filename: str
    sha256: str
    generated_at_utc: str
    report_id: str

    def to_sidecar_text(self) -> str:
        """
        Human-readable + machine-parseable sidecar format: a small JSON
        document. JSON (rather than the bare `sha256sum`-style
        "<hash>  <filename>" line) is used so report_id and timestamp
        travel with the hash, matching the brief's required fields.
        """
        return json.dumps(
            {
                "pdf_filename": self.pdf_filename,
                "sha256": self.sha256,
                "generated_at_utc": self.generated_at_utc,
                "report_id": self.report_id,
            },
            indent=2,
        )

    @classmethod
    def from_sidecar_text(cls, text: str) -> "IntegrityRecord":
        data = json.loads(text)
        return cls(
            pdf_filename=data["pdf_filename"],
            sha256=data["sha256"],
            generated_at_utc=data["generated_at_utc"],
            report_id=data["report_id"],
        )


def generate_integrity_sidecar(pdf_path: PathLike, report_id: str) -> tuple[str, IntegrityRecord]:
    """
    Hashes an already-finalized PDF and writes `<pdf_path>.sha256` next to
    it. Must be called AFTER the PDF is fully written and closed -- hashing
    a PDF mid-write would produce a hash that doesn't match the final file.

    Returns (sidecar_path, IntegrityRecord).
    """
    pdf_path = Path(pdf_path)
    digest = _sha256_of_file(pdf_path)

    record = IntegrityRecord(
        pdf_filename=pdf_path.name,
        sha256=digest,
        generated_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        report_id=report_id,
    )

    sidecar_path = pdf_path.with_suffix(pdf_path.suffix + ".sha256")
    sidecar_path.write_text(record.to_sidecar_text(), encoding="utf-8")

    return str(sidecar_path), record


@dataclass
class VerificationResult:
    verified: bool
    expected_sha256: str
    actual_sha256: str
    report_id: str
    message: str

    @property
    def status_label(self) -> str:
        return "✓ VERIFIED" if self.verified else "✗ MODIFIED"


def verify_report_integrity(pdf_path: PathLike, sidecar_path: PathLike) -> VerificationResult:
    """
    Re-hashes `pdf_path` and compares it against the hash recorded in
    `sidecar_path`. This is the canonical check: "has this report been
    altered since it was generated?"
    """
    record = IntegrityRecord.from_sidecar_text(Path(sidecar_path).read_text(encoding="utf-8"))
    actual = _sha256_of_file(pdf_path)
    verified = actual.lower() == record.sha256.lower()

    return VerificationResult(
        verified=verified,
        expected_sha256=record.sha256,
        actual_sha256=actual,
        report_id=record.report_id,
        message=(
            "File hash matches the recorded value -- report is unmodified."
            if verified
            else "File hash does NOT match the recorded value -- report may have been altered."
        ),
    )
