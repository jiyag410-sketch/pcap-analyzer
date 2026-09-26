"""
pdf_report.py
Builds a professional digital-forensics PDF report from already-computed
analysis results (records, stats, IOCs, alerts, credential findings).

This module does NOT re-parse the pcap or re-run any detector -- every
argument is a value the caller (app.py) already has in memory from the
existing cached analysis functions in performance.py. It only formats
those values into a document.

The existing Markdown report (report_generator.py) is untouched and still
works exactly as before; this is an additive, alternate export.

Evidence integrity: see report_integrity.py. This module writes the PDF,
hands it off to generate_integrity_sidecar() to hash + sidecar it, and
prints the resulting hash algorithm/report-id/pointer-to-sidecar into a
dedicated "Evidence Integrity" section -- it never embeds a self-hash.
"""

from __future__ import annotations

import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from calculate_statistics import CaptureStatistics
from detectors.beaconing import BeaconAlert
from detectors.dns_tunneling import DNSTunnelAlert
from detectors.plaintext_creds import CredAlert
from detectors.port_scan import PortScanAlert
from ioc_extractor import IOCReport
from models import PacketRecord
from password_detector import CredentialFinding
from report_integrity import generate_integrity_sidecar, new_report_id

TOOL_VERSION = "PCAP Forensic Analyzer 2.0 (PDF export)"

_NAVY = colors.HexColor("#0a0e17")
_ACCENT = colors.HexColor("#0891b2")
_MUTED = colors.HexColor("#64748b")
_BORDER = colors.HexColor("#cbd5e1")
_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#f43f5e"),
    "HIGH": colors.HexColor("#fb923c"),
    "MEDIUM": colors.HexColor("#facc15"),
    "LOW": colors.HexColor("#38bdf8"),
}

from dataclasses import dataclass
from typing import Optional

@dataclass
class CaseInfo:
    project_title: str = "PCAP Forensic Analyzer"

    analyst_name: Optional[str] = None
    case_number: Optional[str] = None
    evidence_number: Optional[str] = None
    case_title: Optional[str] = None
    organization: Optional[str] = None
    remarks: Optional[str] = None


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name="H1Cover", fontSize=26, leading=30, textColor=_NAVY,
                           spaceAfter=6, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle(name="SubCover", fontSize=13, textColor=_MUTED, spaceAfter=24))
    ss.add(ParagraphStyle(name="SectionHeading", fontSize=15, textColor=_NAVY,
                           spaceBefore=18, spaceAfter=8, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle(name="SubHeading", fontSize=11.5, textColor=_ACCENT,
                           spaceBefore=10, spaceAfter=4, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle(name="BodySmall", fontSize=9.5, leading=13))
    ss.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=8.5, leading=11))
    return ss


def _kv_table(rows: list[tuple[str, str]], col_widths=(1.8 * inch, 4.4 * inch)) -> Table:
    data = [[Paragraph(f"<b>{k}</b>", ParagraphStyle("k", fontSize=9.5)),
             Paragraph(str(v), ParagraphStyle("v", fontSize=9.5, fontName="Courier"))]
            for k, v in rows]
    t = Table(data, colWidths=list(col_widths))
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, _BORDER),
    ]))
    return t


def _data_table(headers: list[str], rows: list[list[str]], col_widths=None) -> Table:
    if not rows:
        rows = [["None detected."] + [""] * (len(headers) - 1)]
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, _BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _severity_chip_text(sev: str) -> str:
    color = _SEVERITY_COLORS.get((sev or "").upper())
    hexcode = color.hexval()[2:] if color else "64748b"
    return f'<font color="#{hexcode}"><b>{sev or "N/A"}</b></font>'


def _protocol_chart_image(records: list[PacketRecord]) -> Optional[str]:
    """
    Renders a protocol-distribution bar chart to a temp PNG using
    matplotlib (no browser/kaleido dependency) for embedding in the PDF.
    Returns the temp file path, or None if there's nothing to chart.
    """
    counts = Counter(r.protocol for r in records if r.protocol)
    if not counts:
        return None

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    top = counts.most_common(10)
    labels = [k for k, _ in top]
    values = [v for _, v in top]

    fig, ax = plt.subplots(figsize=(6.2, 2.6), dpi=150)
    ax.bar(labels, values, color="#0891b2")
    ax.set_title("Protocol Distribution", fontsize=10)
    ax.tick_params(axis="x", rotation=30, labelsize=8)
    ax.tick_params(axis="y", labelsize=8)
    fig.tight_layout()

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    fig.savefig(tmp.name)
    plt.close(fig)
    return tmp.name


def _header_footer(canvas, doc, report_id: str, pcap_name: str):
    canvas.saveState()
    width, height = letter

    canvas.setFillColor(_NAVY)
    canvas.rect(0, height - 0.45 * inch, width, 0.45 * inch, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(0.5 * inch, height - 0.3 * inch, "PCAP FORENSIC ANALYSIS REPORT")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 0.5 * inch, height - 0.3 * inch, pcap_name[:60])

    canvas.setFillColor(_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(0.5 * inch, 0.35 * inch, f"Report ID: {report_id}")
    canvas.drawRightString(width - 0.5 * inch, 0.35 * inch, f"Page {doc.page}")
    canvas.setStrokeColor(_BORDER)
    canvas.line(0.5 * inch, 0.5 * inch, width - 0.5 * inch, 0.5 * inch)
    canvas.restoreState()


def generate_pdf_report(
    output_path: str,
    pcap_name: str,
    file_size_bytes: int,
    hashes: dict[str, str],
    records: list[PacketRecord],
    stats: CaptureStatistics,
    iocs: IOCReport,
    port_scan_alerts: list[PortScanAlert],
    beacon_alerts: list[BeaconAlert],
    dns_alerts: list[DNSTunnelAlert],
    cred_alerts: list[CredAlert],
    credential_findings: list[CredentialFinding],
    case_info: Optional[CaseInfo] = None,
    report_id: Optional[str] = None,
) -> tuple[str, str, str]:
    """
    Builds the PDF, then (only after it's fully written) generates the
    detached SHA-256 sidecar. Returns (pdf_path, sidecar_path, report_id).
    """
    case_info = case_info or CaseInfo()
    report_id = report_id or new_report_id()
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    styles = _styles()
    story = []

    # ---------------- Cover page ----------------
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("🛡 PCAP Forensic Analysis Report", styles["H1Cover"]))
    story.append(Paragraph("Automated Digital Forensics &amp; Network Threat Detection", styles["SubCover"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(_kv_table([
    ("Report ID", report_id),
    ("Generated", generated_at),
    ("Case Number", case_info.case_number or "N/A"),
    ("Evidence Number", case_info.evidence_number or "N/A"),
    ("Case Title", case_info.case_title or "N/A"),
    ("Organization", case_info.organization or "N/A"),
    ("Investigator", case_info.analyst_name or "Not specified"),
    ("Tool Version", TOOL_VERSION),
    ("Evidence File", pcap_name),
    ]))
    story.append(PageBreak())

    # ---------------- Capture information ----------------
    story.append(Paragraph("Capture Information", styles["SectionHeading"]))
    duration = getattr(stats, "capture_duration", 0.0) or 0.0
    start_dt = min((r.timestamp for r in records), default=None)
    end_dt = max((r.timestamp for r in records), default=None)
    story.append(_kv_table([
        ("Filename", pcap_name),
        ("File Size", f"{file_size_bytes:,} bytes"),
        ("Packet Count", f"{stats.total_packets:,}"),
        ("Capture Duration", f"{duration:.2f} seconds"),
        ("Capture Start", datetime.fromtimestamp(start_dt).isoformat(sep=" ") if start_dt else "N/A"),
        ("Capture End", datetime.fromtimestamp(end_dt).isoformat(sep=" ") if end_dt else "N/A"),
    ]))

        # ---------------- Executive summary ----------------
    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))

    total_alerts = (
        len(port_scan_alerts)
        + len(beacon_alerts)
        + len(dns_alerts)
        + len(cred_alerts)
    )

    risk = "LOW"
    if total_alerts >= 10:
        risk = "HIGH"
    elif total_alerts >= 5:
        risk = "MEDIUM"

    story.append(
        Paragraph(
            f"<b>Overall Risk Level:</b> {risk}",
            styles["BodySmall"],
        )
    )

    story.append(Spacer(1, 0.12 * inch))

    cred_high_risk = sum(
        1
        for f in credential_findings
        if f.severity in ("CRITICAL", "HIGH")
    )

    risk_line = (
        "No high-severity indicators were observed in this capture."
        if total_alerts == 0 and cred_high_risk == 0
        else (
            f"This capture produced {total_alerts} detector alert(s) and "
            f"{cred_high_risk} high/critical-severity credential exposure(s), "
            "warranting analyst review."
        )
    )

    story.append(
        Paragraph(
            f"This report summarizes automated analysis of <b>{pcap_name}</b>, "
            f"covering {stats.total_packets:,} packets across "
            f"{stats.unique_ips} unique hosts and "
            f"{stats.protocol_count} protocols. {risk_line}",
            styles["BodySmall"],
        )
    )    # ---------------- Network statistics ----------------
    story.append(Paragraph("Network Statistics", styles["SectionHeading"]))

    protocol_counts = Counter(r.protocol for r in records if r.protocol)
    story.append(Paragraph("Protocol Distribution", styles["SubHeading"]))
    story.append(_data_table(
        ["Protocol", "Packets", "% of Total"],
        [[p, f"{c:,}", f"{c / stats.total_packets * 100:.1f}%"] for p, c in protocol_counts.most_common()]
        if stats.total_packets else [],
        col_widths=[2 * inch, 1.5 * inch, 1.5 * inch],
    ))

    chart_path = _protocol_chart_image(records)
    if chart_path:
        story.append(Spacer(1, 6))
        story.append(Image(chart_path, width=5.5 * inch, height=2.3 * inch))

    src_counts = Counter(r.src_ip for r in records if r.src_ip)
    dst_counts = Counter(r.dst_ip for r in records if r.dst_ip)
    port_counts = Counter(r.dst_port for r in records if r.dst_port)

    story.append(Paragraph("Top Source IPs", styles["SubHeading"]))
    story.append(_data_table(["Source IP", "Packets"],
                              [[ip, f"{c:,}"] for ip, c in src_counts.most_common(10)],
                              col_widths=[3 * inch, 2 * inch]))

    story.append(Paragraph("Top Destination IPs", styles["SubHeading"]))
    story.append(_data_table(["Destination IP", "Packets"],
                              [[ip, f"{c:,}"] for ip, c in dst_counts.most_common(10)],
                              col_widths=[3 * inch, 2 * inch]))

    story.append(Paragraph("Top Destination Ports", styles["SubHeading"]))
    story.append(_data_table(["Port", "Packets"],
                              [[str(p), f"{c:,}"] for p, c in port_counts.most_common(10)],
                              col_widths=[3 * inch, 2 * inch]))

    # Conversation counts computed directly (rather than importing
    # communication_graph.build_graph, which pulls in networkx/plotly
    # purely for an interactive figure this static report doesn't need).
    conversation_counts = Counter(
        (r.src_ip, r.dst_ip) for r in records if r.src_ip and r.dst_ip
    )
    convo_rows = [(u, v, c) for (u, v), c in conversation_counts.most_common(15)]
    story.append(Paragraph("Top Conversations", styles["SubHeading"]))
    story.append(_data_table(["Source", "Destination", "Packets"],
                              [[u, v, str(c)] for u, v, c in convo_rows],
                              col_widths=[2.2 * inch, 2.2 * inch, 1.5 * inch]))

    story.append(PageBreak())

    # ---------------- Network artifacts ----------------
    story.append(Paragraph("Network Artifacts", styles["SectionHeading"]))
    d = iocs.to_dict()

    story.append(Paragraph("DNS Queries / Domains", styles["SubHeading"]))
    story.append(Paragraph(", ".join(d["domains"]) or "None observed.", styles["Mono"]))

    story.append(Paragraph("URLs", styles["SubHeading"]))
    story.append(Paragraph("<br/>".join(d["urls"]) or "None observed.", styles["Mono"]))

    story.append(Paragraph("TLS SNI / Email Addresses / User-Agents", styles["SubHeading"]))
    story.append(Paragraph(
        "Not extracted by the current parser (pcap_parser.py records DNS/HTTP host, "
        "path, and payload snippets only; TLS SNI, email header, and User-Agent "
        "extraction are not part of the existing parsing logic and were intentionally "
        "left unmodified for this release).",
        styles["BodySmall"],
    ))

    # ---------------- Security findings ----------------
    story.append(Paragraph("Security Findings", styles["SectionHeading"]))

    def alert_rows(alerts):
        return [[getattr(a, "severity", "N/A"), a.summary()] for a in alerts]

    story.append(Paragraph(f"Port Scan Alerts ({len(port_scan_alerts)})", styles["SubHeading"]))
    story.append(_data_table(["Severity", "Detail"], alert_rows(port_scan_alerts),
                              col_widths=[0.9 * inch, 5.1 * inch]))

    story.append(Paragraph(f"Beaconing / C2 Alerts ({len(beacon_alerts)})", styles["SubHeading"]))
    story.append(_data_table(["Severity", "Detail"], alert_rows(beacon_alerts),
                              col_widths=[0.9 * inch, 5.1 * inch]))

    story.append(Paragraph(f"DNS Tunneling Alerts ({len(dns_alerts)})", styles["SubHeading"]))
    story.append(_data_table(["Severity", "Detail"], alert_rows(dns_alerts),
                              col_widths=[0.9 * inch, 5.1 * inch]))

    story.append(Paragraph(f"IOC Summary", styles["SubHeading"]))
    story.append(_data_table(
        ["Indicator", "Count"],
        [["External IPs", str(len(d["external_ips"]))],
         ["Domains", str(len(d["domains"]))],
         ["URLs", str(len(d["urls"]))]],
        col_widths=[3 * inch, 2 * inch],
    ))

    story.append(PageBreak())

    # ---------------- Credential analysis ----------------
    story.append(Paragraph("Credential Analysis", styles["SectionHeading"]))
    story.append(Paragraph(
        f"{len(credential_findings)} credential-relevant finding(s) detected across HTTP, FTP, "
        f"POP3/IMAP, SMTP, Telnet, IRC, cookies, tokens, and API-key-shaped values. "
        f"Additionally, the existing plaintext-credential detector separately flagged "
        f"{len(cred_alerts)} finding(s) (shown under Security Findings' legacy alert stream).",
        styles["BodySmall"],
    ))

    cred_rows = [
        [
            f.severity, f.field_type, f.field_name or "",
            f.value[:60], f.src_ip, f.dst_ip, "Yes" if f.reused else "No",
        ]
        for f in sorted(credential_findings, key=lambda x: x.timestamp)
    ]
    story.append(_data_table(
        ["Severity", "Type", "Field", "Value (truncated)", "Source", "Destination", "Reused"],
        cred_rows,
        col_widths=[0.75 * inch, 0.85 * inch, 0.75 * inch, 1.6 * inch, 1.1 * inch, 1.1 * inch, 0.65 * inch],
    ))

    weak_or_default = [f for f in credential_findings if any(
        "weak" in r or "default" in r for r in f.reasons)]
    if weak_or_default:
        story.append(Paragraph("Weak / Default Passwords Flagged", styles["SubHeading"]))
        story.append(_data_table(
            ["Value", "Source", "Destination", "Reason"],
            [[f.value[:40], f.src_ip, f.dst_ip, "; ".join(f.reasons)] for f in weak_or_default],
            col_widths=[1.4 * inch, 1.3 * inch, 1.3 * inch, 2 * inch],
        ))

    story.append(PageBreak())

    # ---------------- Timeline ----------------
    story.append(Paragraph("Timeline", styles["SectionHeading"]))
    story.append(Paragraph(
        "Chronological summary of every detector alert and credential finding "
        "(the full packet-by-packet timeline is available in the Packet Viewer tab "
        "and CSV exports; this table is condensed to security-relevant events for "
        "report readability).",
        styles["BodySmall"],
    ))

    timeline_events = []
    for a in port_scan_alerts:
        timeline_events.append((a.timestamp, "Port Scan", getattr(a, "severity", "N/A"), a.summary()))
    for a in beacon_alerts:
        timeline_events.append((a.timestamp, "Beaconing", getattr(a, "severity", "N/A"), a.summary()))
    for a in dns_alerts:
        timeline_events.append((a.timestamp, "DNS Tunneling", getattr(a, "severity", "N/A"), a.summary()))
    for a in cred_alerts:
        timeline_events.append((a.timestamp, "Plaintext Credential", getattr(a, "severity", "N/A"), a.summary()))
    for f in credential_findings:
        timeline_events.append((f.timestamp, "Credential Finding", f.severity, f.summary()))
    timeline_events.sort(key=lambda e: e[0])

    story.append(_data_table(
        ["Time", "Category", "Severity", "Detail"],
        [[datetime.fromtimestamp(t).strftime("%H:%M:%S"), cat, sev, detail[:80]]
         for t, cat, sev, detail in timeline_events[:200]],
        col_widths=[0.8 * inch, 1.2 * inch, 0.8 * inch, 3.2 * inch],
    ))
    if len(timeline_events) > 200:
        story.append(Paragraph(
            f"... {len(timeline_events) - 200} additional event(s) omitted for length; "
            "see the Markdown report or dashboard for the complete list.",
            styles["BodySmall"],
        ))

    story.append(PageBreak())

    # ---------------- Appendix ----------------
    story.append(Paragraph("Appendix — Summary Tables", styles["SectionHeading"]))
    story.append(_kv_table([
        ("Total Packets", f"{stats.total_packets:,}"),
        ("Unique IPs", str(stats.unique_ips)),
        ("Sessions", str(stats.sessions)),
        ("Protocols Observed", str(stats.protocol_count)),
        ("Total Bytes", f"{stats.total_bytes:,}"),
        ("Total Alerts", str(total_alerts)),
        ("Credential Findings", str(len(credential_findings))),
    ]))

    story.append(Paragraph("Evidence Hashes (Original Capture File)", styles["SubHeading"]))
    story.append(_kv_table([(k, v) for k, v in hashes.items()]))

    story.append(Paragraph("Investigator Remarks", styles["SectionHeading"]))

    story.append(
    Paragraph(
        case_info.remarks or "No remarks were provided by the investigator.",
        styles["BodySmall"],
    )
    )

    # ---------------- Evidence integrity ----------------
    story.append(PageBreak())
    story.append(Paragraph("Evidence Integrity", styles["SectionHeading"]))
    story.append(Paragraph(
        "This report's own file integrity is verified via a detached SHA-256 hash, "
        "generated <b>after</b> this PDF was finalized and written separately -- the "
        "hash is never embedded inside the PDF itself, since doing so would change "
        "the file's contents (and therefore its hash) after the fact.",
        styles["BodySmall"],
    ))
    story.append(Spacer(1, 8))
    story.append(_kv_table([
        ("Algorithm", "SHA-256"),
        ("Generated", generated_at + " (local)"),
        ("Report ID", report_id),
        ("Verification", "Use the accompanying .sha256 file to verify this report has not been modified."),
    ]))

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.7 * inch, bottomMargin=0.65 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        title=f"PCAP Forensic Report - {pcap_name}",
    )

    def _on_page(canvas, doc_):
        _header_footer(canvas, doc_, report_id, pcap_name)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)

    if chart_path:
        try:
            Path(chart_path).unlink(missing_ok=True)
        except OSError:
            pass

    # Hash + sidecar AFTER the PDF is fully written and closed.
    sidecar_path, _record = generate_integrity_sidecar(output_path, report_id)

    return output_path, sidecar_path, report_id
