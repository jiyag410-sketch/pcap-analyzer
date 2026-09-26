"""
hash_verifier.py
Command-line utility for verifying a forensic PDF report against its
detached `.sha256` sidecar file. All the actual hashing/comparison logic
lives in report_integrity.py -- this module is just the CLI entry point.

Usage:
    python hash_verifier.py pcap_forensic_report.pdf pcap_forensic_report.pdf.sha256

    # or, if the sidecar sits next to the PDF with the default name:
    python hash_verifier.py pcap_forensic_report.pdf
"""

from __future__ import annotations

import sys
from pathlib import Path

from report_integrity import verify_report_integrity


def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: python hash_verifier.py <report.pdf> [report.pdf.sha256]")
        return 2

    pdf_path = Path(argv[0])
    sidecar_path = Path(argv[1]) if len(argv) > 1 else pdf_path.with_suffix(pdf_path.suffix + ".sha256")

    if not pdf_path.exists():
        print(f"Error: PDF not found: {pdf_path}")
        return 2
    if not sidecar_path.exists():
        print(f"Error: sidecar hash file not found: {sidecar_path}")
        return 2

    result = verify_report_integrity(pdf_path, sidecar_path)

    print(f"Report ID:     {result.report_id}")
    print(f"Expected hash: {result.expected_sha256}")
    print(f"Actual hash:   {result.actual_sha256}")
    print(f"Result:        {result.status_label}")
    print(result.message)

    return 0 if result.verified else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
