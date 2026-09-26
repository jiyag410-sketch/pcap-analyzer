"""
pcap_parser.py
Parses a .pcap/.pcapng file into a clean, structured list of packet records
that the rest of the tool (detectors, IOC extractor, report generator) can
work with, instead of every module re-parsing raw scapy objects.
"""

from __future__ import annotations
from typing import Optional
import re

from scapy.all import rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest  # requires scapy's http layer

from models import PacketRecord

try:
    from scapy.packet import Raw
except ImportError:  # pragma: no cover
    Raw = None


def _proto_name(pkt: Packet) -> str:
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(HTTPRequest):
        return "HTTP"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP):
        return "IP"
    return "OTHER"


def parse_pcap(path: str, max_packets: Optional[int] = None) -> list[PacketRecord]:
    """
    Reads a pcap file and returns a list of PacketRecord objects.
    max_packets caps how many packets are parsed (useful for huge captures
    during development/testing).
    """
    packets = rdpcap(path)
    records: list[PacketRecord] = []

    for i, pkt in enumerate(packets):
        if max_packets and i >= max_packets:
            break

        rec = PacketRecord(
            index=i,
            timestamp=float(pkt.time),
            length=len(pkt),
            protocol=_proto_name(pkt),
        )

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            rec.src_ip = ip_layer.src
            rec.dst_ip = ip_layer.dst

        if pkt.haslayer(TCP):
            rec.src_port = int(pkt[TCP].sport)
            rec.dst_port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            rec.src_port = int(pkt[UDP].sport)
            rec.dst_port = int(pkt[UDP].dport)

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                rec.dns_query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                pass

        if pkt.haslayer(HTTPRequest):
            http = pkt[HTTPRequest]
            rec.http_host = http.Host.decode(errors="ignore") if http.Host else None
            rec.http_path = http.Path.decode(errors="ignore") if http.Path else None

        if Raw is not None and pkt.haslayer(Raw):
            try:
                raw_bytes = bytes(pkt[Raw].load)
                # keep a small printable snippet only -- full payload isn't needed
                snippet = re.sub(rb"[^\x20-\x7e]", b".", raw_bytes[:256])
                rec.payload_snippet = snippet.decode(errors="ignore")
            except Exception:
                pass

        records.append(rec)

    return records
