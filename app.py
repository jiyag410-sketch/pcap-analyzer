"""
PCAP Forensic Analyzer
Streamlit Dashboard
Run:
python -m streamlit run app.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from report_generator import generate_report
from visualization.charts import protocol_pie_chart

from config import APP_CONFIG
from performance import (
    calculate_hashes_cached,
    calculate_statistics_cached,
    create_graph_figure_cached,
    detect_credentials_cached,
    extract_iocs_cached,
    parse_pcap_cached,
    run_all_detectors_cached,
)
from ui_components import (
    render_footer,
    render_hero_banner,
    render_metric_card,
    style_plotly_figure,
)
from theme_manager import inject_selected_theme, render_theme_toggle
from password_detector import findings_to_dicts
from pdf_report import CaseInfo, generate_pdf_report
from report_integrity import verify_report_integrity

# ==========================================================
# PAGE CONFIG
# ==========================================================

st.set_page_config(
    page_title=APP_CONFIG.page_title,
    page_icon=APP_CONFIG.page_icon,
    layout=APP_CONFIG.layout,
)

# ==========================================================
# SIDEBAR
# ==========================================================

st.sidebar.title("⚙ Analysis Settings")

if APP_CONFIG.enable_custom_theme:
    render_theme_toggle()
    inject_selected_theme()
    # ==========================================================
# CASE INFORMATION
# ==========================================================

st.sidebar.markdown("---")
st.sidebar.subheader("🕵 Investigation Details")

case_number = st.sidebar.text_input(
    "Case Number",
    value="CASE-2026-001"
)

evidence_number = st.sidebar.text_input(
    "Evidence Number",
    value="EVD-001"
)

case_title = st.sidebar.text_input(
    "Case Title",
    value="Network Traffic Investigation"
)

organization = st.sidebar.text_input(
    "Organization",
    value="Cyber Security Laboratory"
)

render_hero_banner(
    title="🛡 PCAP Forensic Analyzer",
    subtitle="Automated Digital Forensics & Network Threat Detection Dashboard",
)

max_packets = st.sidebar.number_input(
    "Maximum packets to parse",
    min_value=0,
    value=0,
    step=1000,
    help="0 means parse the entire capture.",
)

analyst_name = st.sidebar.text_input(
    "Investigator Name",
    value="",
    help="Name of the investigator."
)

remarks = st.sidebar.text_area(
    "Investigator Remarks",
    height=100,
    placeholder="Enter investigation notes..."
)

uploaded = st.file_uploader(
    "Upload a PCAP / PCAPNG file",
    type=["pcap", "pcapng"],
)

# ==========================================================
# MAIN APPLICATION
# ==========================================================

if uploaded is not None:

    file_bytes = uploaded.getvalue()

    hashes = calculate_hashes_cached(file_bytes)

    # ------------------------------------------------------

    with st.spinner("Parsing PCAP..."):

        try:
            records = parse_pcap_cached(
                file_bytes,
                max_packets or None,
            )

        except Exception as e:

            st.error(f"❌ Error parsing PCAP file:\n\n{e}")

            st.stop()

    st.success(
        f"Successfully parsed {len(records):,} packets."
    )
    st.info(
    f"""
        **Case Number:** {case_number}

        **Evidence Number:** {evidence_number}

        **Investigator:** {analyst_name if analyst_name else 'Not specified'}

        **Organization:** {organization}
        """
    )

    # ------------------------------------------------------

    with st.spinner("Running forensic analysis..."):

        stats = calculate_statistics_cached(records)

        iocs = extract_iocs_cached(records)

        port_scan_alerts, beacon_alerts, dns_alerts, cred_alerts = run_all_detectors_cached(records)

        credential_findings = detect_credentials_cached(records)

    total_alerts = (
        len(port_scan_alerts)
        + len(beacon_alerts)
        + len(dns_alerts)
        + len(cred_alerts)
    )

    # ======================================================
    # DASHBOARD SUMMARY
    # ======================================================

    st.subheader("📈 Dashboard Overview")

    c1, c2, c3 = st.columns(3)
    c4, c5, c6 = st.columns(3)

    with c1:
        render_metric_card("📦", "Total Packets", f"{stats.total_packets:,}")
    with c2:
        render_metric_card("🌐", "Unique IPs", str(stats.unique_ips))
    with c3:
        render_metric_card("🔗", "Sessions", str(stats.sessions))
    with c4:
        render_metric_card("📡", "Protocols", str(stats.protocol_count))
    with c5:
        render_metric_card("💾", "Traffic", f"{stats.total_bytes:,} Bytes")
    with c6:
        render_metric_card("🚨", "Alerts", str(total_alerts))

    st.divider()

    # ======================================================
    # EVIDENCE INTEGRITY
    # ======================================================

    st.subheader("🛡 Evidence Integrity")

    h1, h2, h3 = st.columns(3)

    with h1:

        st.markdown("### MD5")

        st.code(
            hashes["MD5"],
            language=None,
        )

    with h2:

        st.markdown("### SHA1")

        st.code(
            hashes["SHA1"],
            language=None,
        )

    with h3:

        st.markdown("### SHA256")

        st.code(
            hashes["SHA256"],
            language=None,
        )

    st.divider()

    # ======================================================
    # MAIN TABS
    # ======================================================

    (
    tab_stats,
    tab_alerts,
    tab_creds,
    tab_iocs,
    tab_packets,
    tab_graph,
    tab_timeline,
    tab_report,
) = st.tabs(
    [
        "📊 Statistics",
        "🚨 Alerts",
        "🔑 Passwords & Credentials",
        "📋 IOCs",
        "📦 Packet Viewer",
        "🌐 Network Graph",
        "🕒 Timeline",
        "📄 Report",
    ]
)
    # ======================================================
    # STATISTICS TAB
    # ======================================================

    with tab_stats:

        st.header("📊 Traffic Statistics")

        protocol_df = pd.DataFrame({
            "Protocol": [
                r.protocol
                for r in records
                if r.protocol
            ]
        })

        if not protocol_df.empty:

            protocol_counts = (
                protocol_df["Protocol"]
                .value_counts()
                .reset_index()
            )

            protocol_counts.columns = [
                "Protocol",
                "Count",
            ]

            pie_fig = style_plotly_figure(protocol_pie_chart(records))

            bar_fig = style_plotly_figure(px.bar(
                protocol_counts,
                x="Protocol",
                y="Count",
                text="Count",
                title="Protocol Usage",
            ))

            left, right = st.columns(2)

            with left:
                st.plotly_chart(
                    pie_fig,
                    use_container_width=True,
                )

            with right:
                st.plotly_chart(
                    bar_fig,
                    use_container_width=True,
                )

        else:

            st.info(
                "No protocol information available."
            )

        st.divider()

        # ==============================================

        source_df = pd.DataFrame({
            "Source IP": [
                r.src_ip
                for r in records
                if r.src_ip
            ]
        })

        destination_df = pd.DataFrame({
            "Destination IP": [
                r.dst_ip
                for r in records
                if r.dst_ip
            ]
        })

        col1, col2 = st.columns(2)

        with col1:

            if not source_df.empty:

                top_sources = (
                    source_df["Source IP"]
                    .value_counts()
                    .head(10)
                    .reset_index()
                )

                top_sources.columns = [
                    "IP Address",
                    "Packets",
                ]

                src_fig = style_plotly_figure(px.bar(
                    top_sources,
                    x="IP Address",
                    y="Packets",
                    text="Packets",
                    title="Top Source IPs",
                ))

                st.plotly_chart(
                    src_fig,
                    use_container_width=True,
                )

        with col2:

            if not destination_df.empty:

                top_destinations = (
                    destination_df["Destination IP"]
                    .value_counts()
                    .head(10)
                    .reset_index()
                )

                top_destinations.columns = [
                    "IP Address",
                    "Packets",
                ]

                dst_fig = style_plotly_figure(px.bar(
                    top_destinations,
                    x="IP Address",
                    y="Packets",
                    text="Packets",
                    title="Top Destination IPs",
                ))

                st.plotly_chart(
                    dst_fig,
                    use_container_width=True,
                )

        st.divider()
    # ======================================================
    # ALERTS TAB
    # ======================================================

    with tab_alerts:

        st.header("🚨 Threat Detection Dashboard")

        high = (
            len(port_scan_alerts)
            + len(beacon_alerts)
            + len(dns_alerts)
        )

        medium = len(cred_alerts)

        total = high + medium

        c1, c2, c3 = st.columns(3)

        c1.metric("🔴 High Severity", high)
        c2.metric("🟠 Medium Severity", medium)
        c3.metric("🚨 Total Alerts", total)

        st.divider()

        with st.expander(
            f"🔍 Port Scan Alerts ({len(port_scan_alerts)})",
            expanded=True,
        ):

            if port_scan_alerts:

                st.dataframe(
                    pd.DataFrame([
                        {
                            "Severity": a.severity,
                            "Source IP": a.src_ip,
                            "Distinct Ports": a.distinct_ports,
                            "Targets": len(a.dst_ips),
                        }
                        for a in port_scan_alerts
                    ]),
                    use_container_width=True,
                )

            else:
                st.success("No Port Scan activity detected.")

        with st.expander(
            f"📡 Beaconing ({len(beacon_alerts)})"
        ):

            if beacon_alerts:

                st.dataframe(
                    pd.DataFrame([
                        {
                            "Severity": a.severity,
                            "Source": a.src_ip,
                            "Destination": a.dst_ip,
                            "Connections": a.connection_count,
                            "Avg Interval (s)": round(
                                a.avg_interval_seconds,
                                2,
                            ),
                        }
                        for a in beacon_alerts
                    ]),
                    use_container_width=True,
                )

            else:
                st.success("No Beaconing detected.")

        with st.expander(
            f"🌐 DNS Tunneling ({len(dns_alerts)})"
        ):

            if dns_alerts:

                st.dataframe(
                    pd.DataFrame([
                        {
                            "Severity": a.severity,
                            "Root Domain": a.root_domain,
                            "Queries": a.query_count,
                            "Entropy": round(
                                a.avg_entropy,
                                2,
                            ),
                        }
                        for a in dns_alerts
                    ]),
                    use_container_width=True,
                )

            else:
                st.success("No DNS Tunneling detected.")

        with st.expander(
            f"🔑 Plaintext Credentials ({len(cred_alerts)})"
        ):

            if cred_alerts:

                st.dataframe(
                    pd.DataFrame([
                        {
                            "Severity": a.severity,
                            "Type": a.kind,
                            "Source": a.src_ip,
                            "Destination": a.dst_ip,
                            "Matched": a.matched_text,
                        }
                        for a in cred_alerts
                    ]),
                    use_container_width=True,
                )

            else:
                st.success("No Plaintext Credentials detected.")

    # ======================================================
    # PASSWORDS & CREDENTIALS TAB
    # ======================================================

    with tab_creds:

        st.header("🔑 Passwords & Credentials")

        st.caption(
            "Broader credential/secret scan (HTTP forms, JSON/XML bodies, Basic/Bearer "
            "auth, cookies, JWTs, API keys, FTP/POP3/IMAP/SMTP/Telnet/IRC). Separate from, "
            "and additional to, the 'Plaintext Credentials' alerts under the Alerts tab."
        )

        if credential_findings:

            sev_counts = pd.Series(
                [f.severity for f in credential_findings]
            ).value_counts()

            m1, m2, m3, m4 = st.columns(4)
            with m1:
                render_metric_card("🔴", "Critical", str(sev_counts.get("CRITICAL", 0)))
            with m2:
                render_metric_card("🟠", "High", str(sev_counts.get("HIGH", 0)))
            with m3:
                render_metric_card("🟡", "Medium", str(sev_counts.get("MEDIUM", 0)))
            with m4:
                render_metric_card("🔵", "Low", str(sev_counts.get("LOW", 0)))

            st.divider()

            cred_df = pd.DataFrame(findings_to_dicts(credential_findings))

            sev_filter = st.multiselect(
                "Filter by severity",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            )
            filtered_df = cred_df[cred_df["Severity"].isin(sev_filter)]

            reveal_values = st.checkbox(
                "Show raw credential values",
                value=True,
                help="Uncheck to mask values before sharing your screen.",
            )
            if not reveal_values:
                filtered_df = filtered_df.copy()
                filtered_df["Value"] = "••••••••"

            st.dataframe(
                filtered_df.sort_values("Severity"),
                use_container_width=True,
                height=420,
            )

            st.download_button(
                "⬇ Download Credential Findings (CSV)",
                cred_df.to_csv(index=False),
                file_name="credential_findings.csv",
                mime="text/csv",
            )

            weak_default = [
                f for f in credential_findings
                if any("weak" in r or "default" in r for r in f.reasons)
            ]
            if weak_default:
                with st.expander(f"⚠ Weak / Default Passwords ({len(weak_default)})"):
                    st.dataframe(
                        pd.DataFrame(findings_to_dicts(weak_default)),
                        use_container_width=True,
                    )

            reused = [f for f in credential_findings if f.reused]
            if reused:
                with st.expander(f"♻ Reused Credentials ({len(reused)})"):
                    st.dataframe(
                        pd.DataFrame(findings_to_dicts(reused)),
                        use_container_width=True,
                    )

        else:
            st.success("No credentials or secrets detected in this capture.")

    # ======================================================
    # IOC TAB
    # ======================================================

    with tab_iocs:

        st.header("📋 Indicators of Compromise")

        d = iocs.to_dict()

        col1, col2 = st.columns(2)

        with col1:

            st.subheader("🌐 External IP Addresses")

            external_ips = d.get("external_ips", [])

            if external_ips:

                st.code("\n".join(external_ips))

                ip_df = pd.DataFrame(
                    {"External IP": external_ips}
                )

                st.download_button(
                    "⬇ Download IPs (CSV)",
                    ip_df.to_csv(index=False),
                    file_name="external_ips.csv",
                    mime="text/csv",
                )

            else:
                st.info("None found.")

            st.subheader("🌍 Domains")

            domains = d.get("domains", [])

            if domains:

                st.code("\n".join(domains))

            else:
                st.info("None found.")

        with col2:

            st.subheader("🔗 URLs")

            urls = d.get("urls", [])

            if urls:

                st.code("\n".join(urls))

            else:
                st.info("None found.")

            st.subheader("📈 IOC Summary")

            st.metric(
                "External IPs",
                len(external_ips),
            )

            st.metric(
                "Domains",
                len(domains),
            )

            st.metric(
                "URLs",
                len(urls),
            )

    # ======================================================
    # PACKET VIEWER
    # ======================================================

    with tab_packets:

        st.header("📦 Packet Viewer")

        packet_df = pd.DataFrame([
            {
                "Time": r.dt,
                "Source": r.src_ip,
                "Destination": r.dst_ip,
                "Protocol": r.protocol,
                "Length": r.length,
            }
            for r in records
        ])

        if not packet_df.empty:

            protocol_options = ["All"] + sorted(
                packet_df["Protocol"]
                .dropna()
                .unique()
                .tolist()
            )

            selected_protocol = st.selectbox(
                "Protocol Filter",
                protocol_options,
            )

            if selected_protocol != "All":

                packet_df = packet_df[
                    packet_df["Protocol"]
                    == selected_protocol
                ]

            search_ip = st.text_input(
                "Search Source/Destination IP"
            )

            if search_ip:

                packet_df = packet_df[
                    packet_df["Source"]
                    .fillna("")
                    .str.contains(search_ip, case=False)
                    |
                    packet_df["Destination"]
                    .fillna("")
                    .str.contains(search_ip, case=False)
                ]

            st.dataframe(
                packet_df,
                use_container_width=True,
                height=500,
            )

            st.caption(
                f"Showing {len(packet_df):,} packets."
            )

        else:

            st.info("No packets available.")
    # ======================================================
    # NETWORK GRAPH
    # ======================================================

    # ==========================================================
# NETWORK GRAPH TAB
# ==========================================================

    with tab_graph:

        st.header("🌐 Network Communication Graph")

        st.caption(
            "Visual representation of communication between hosts in the capture."
        )

        graph_fig = style_plotly_figure(create_graph_figure_cached(records))

        if graph_fig is not None:
            st.plotly_chart(
                graph_fig,
                use_container_width=True,
                key="network_graph",
            )
        else:
            st.info("No communication graph could be generated.")
    # ======================================================
    # TIMELINE TAB
    # ======================================================

    with tab_timeline:

        st.header("🕒 Network Timeline")

        timeline_df = pd.DataFrame({
            "Time": [r.dt for r in records],
            "Length": [r.length for r in records],
            "Protocol": [r.protocol for r in records],
        })

        if not timeline_df.empty:

            timeline_df = timeline_df.sort_values("Time")

            packets = (
                timeline_df
                .set_index("Time")
                .resample("1s")
                .size()
                .reset_index(name="Packets")
            )

            fig_packets = style_plotly_figure(px.line(
                packets,
                x="Time",
                y="Packets",
                title="Packets Per Second",
            ))

            st.plotly_chart(
                fig_packets,
                use_container_width=True,
            )

            bandwidth = (
                timeline_df
                .set_index("Time")["Length"]
                .resample("1s")
                .sum()
                .reset_index()
            )

            fig_bandwidth = style_plotly_figure(px.area(
                bandwidth,
                x="Time",
                y="Length",
                title="Bandwidth Usage",
            ))

            st.plotly_chart(
                fig_bandwidth,
                use_container_width=True,
            )

            protocol_timeline = (
                timeline_df
                .groupby("Protocol")
                .size()
                .reset_index(name="Packets")
            )

            fig_protocol = style_plotly_figure(px.bar(
                protocol_timeline,
                x="Protocol",
                y="Packets",
                color="Protocol",
                title="Protocol Timeline Summary",
            ))

            st.plotly_chart(
                fig_protocol,
                use_container_width=True,
            )

        else:

            st.info("No timeline available.")

    # ======================================================
    # REPORT TAB
    # ======================================================

    with tab_report:

        st.header("📄 Investigation Report")

        report_text = generate_report(
        pcap_name=uploaded.name,
        records=records,
        iocs=iocs,
        port_scan_alerts=port_scan_alerts,
        beacon_alerts=beacon_alerts,
        dns_alerts=dns_alerts,
        cred_alerts=cred_alerts,
        credential_findings=credential_findings,
        case_number=case_number,
        evidence_number=evidence_number,
        case_title=case_title,
        investigator=analyst_name,
        organization=organization,
        remarks=remarks,
    )

        st.markdown(report_text)

        st.download_button(
            "⬇ Download Markdown Report",
            report_text,
            file_name="pcap_forensic_report.md",
            mime="text/markdown",
        )

        st.divider()
        st.subheader("Professional Forensic PDF Export")
        st.caption(
            "Cover page, case/capture metadata, network statistics with charts, "
            "artifacts, security findings, credential analysis, timeline, and an "
            "Evidence Integrity section backed by a detached SHA-256 sidecar file."
        )

        if st.button("📄 Generate PDF Report", type="primary"):
            with st.spinner("Building forensic PDF report..."):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    pdf_path = str(Path(tmp_dir) / "pcap_forensic_report.pdf")

                    _, sidecar_path, report_id = generate_pdf_report(
                        output_path=pdf_path,
                        pcap_name=uploaded.name,
                        file_size_bytes=len(file_bytes),
                        hashes=hashes,
                        records=records,
                        stats=stats,
                        iocs=iocs,
                        port_scan_alerts=port_scan_alerts,
                        beacon_alerts=beacon_alerts,
                        dns_alerts=dns_alerts,
                        cred_alerts=cred_alerts,
                        credential_findings=credential_findings,
                        case_info=CaseInfo(
                        analyst_name=analyst_name or None,
                        case_number=case_number,
                        evidence_number=evidence_number,
                        case_title=case_title,
                        organization=organization,
                        remarks=remarks,
                        )
                    )

                    st.session_state["pdf_report_bytes"] = Path(pdf_path).read_bytes()
                    st.session_state["pdf_sidecar_bytes"] = Path(sidecar_path).read_bytes()
                    st.session_state["pdf_report_id"] = report_id

            st.success(f"PDF report generated. Report ID: {st.session_state['pdf_report_id']}")

        if "pdf_report_bytes" in st.session_state:
            col_pdf, col_hash = st.columns(2)
            with col_pdf:
                st.download_button(
                    "⬇ Download PDF Report",
                    st.session_state["pdf_report_bytes"],
                    file_name="pcap_forensic_report.pdf",
                    mime="application/pdf",
                )
            with col_hash:
                st.download_button(
                    "⬇ Download .sha256 Integrity File",
                    st.session_state["pdf_sidecar_bytes"],
                    file_name="pcap_forensic_report.pdf.sha256",
                    mime="application/json",
                )
            st.info(
                "Keep the .sha256 file alongside the PDF. To verify later that the "
                "report hasn't been altered, use the checker below (or "
                "`python hash_verifier.py pcap_forensic_report.pdf`)."
            )

        st.divider()
        st.subheader("Verify Report Integrity")
        st.caption("Upload a previously exported PDF and its matching .sha256 file to confirm it hasn't been modified.")

        vcol1, vcol2 = st.columns(2)
        with vcol1:
            check_pdf = st.file_uploader("Report PDF", type=["pdf"], key="verify_pdf")
        with vcol2:
            check_sha = st.file_uploader("Sidecar .sha256 file", type=["sha256", "json"], key="verify_sha")

        if check_pdf is not None and check_sha is not None:
            if st.button("🔍 Verify Integrity"):
                with tempfile.TemporaryDirectory() as tmp_dir:
                    tmp_pdf = Path(tmp_dir) / "check.pdf"
                    tmp_sidecar = Path(tmp_dir) / "check.pdf.sha256"
                    tmp_pdf.write_bytes(check_pdf.getvalue())
                    tmp_sidecar.write_bytes(check_sha.getvalue())

                    result = verify_report_integrity(tmp_pdf, tmp_sidecar)

                if result.verified:
                    st.success(f"{result.status_label} — {result.message}")
                else:
                    st.error(f"{result.status_label} — {result.message}")
                st.code(
                    f"Report ID:     {result.report_id}\n"
                    f"Expected hash: {result.expected_sha256}\n"
                    f"Actual hash:   {result.actual_sha256}",
                    language="text",
                )

    render_footer()

else:
    st.info(
        "👈 Upload a PCAP or PCAPNG file to begin network analysis.")