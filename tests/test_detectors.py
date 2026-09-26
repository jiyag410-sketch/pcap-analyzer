"""
tests/test_detectors.py
Unit tests for detector logic using synthetic PacketRecord objects, so they
run without needing an actual pcap file. Run with: pytest
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import PacketRecord
from detectors.port_scan import detect_port_scans
from detectors.beaconing import detect_beaconing
from detectors.dns_tunneling import detect_dns_tunneling
from detectors.plaintext_creds import detect_plaintext_creds


def make_record(**kwargs) -> PacketRecord:
    defaults = dict(index=0, timestamp=0.0)
    defaults.update(kwargs)
    return PacketRecord(**defaults)


def test_port_scan_detects_many_ports_fast():
    records = [
        make_record(index=i, timestamp=i * 0.1, src_ip="10.0.0.5",
                    dst_ip="10.0.0.9", dst_port=1000 + i)
        for i in range(20)
    ]
    alerts = detect_port_scans(records, port_threshold=15, window_seconds=10)
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.5"


def test_port_scan_ignores_normal_traffic():
    records = [
        make_record(index=0, timestamp=0.0, src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=443),
        make_record(index=1, timestamp=1.0, src_ip="10.0.0.5", dst_ip="10.0.0.9", dst_port=443),
    ]
    alerts = detect_port_scans(records)
    assert alerts == []


def test_beaconing_detects_regular_intervals():
    records = [
        make_record(index=i, timestamp=i * 60.0, src_ip="10.0.0.5",
                    dst_ip="8.8.8.8", dst_port=443)
        for i in range(10)
    ]
    alerts = detect_beaconing(records)
    assert len(alerts) == 1
    assert alerts[0].dst_ip == "8.8.8.8"


def test_beaconing_ignores_irregular_traffic():
    import random
    random.seed(1)
    t = 0.0
    records = []
    for i in range(10):
        t += random.uniform(1, 500)
        records.append(make_record(index=i, timestamp=t, src_ip="10.0.0.5",
                                    dst_ip="1.2.3.4", dst_port=443))
    alerts = detect_beaconing(records)
    assert alerts == []


def test_dns_tunneling_flags_high_entropy_high_volume():
    records = [
        make_record(index=i, timestamp=i,
                    dns_query=f"kj2h4kjh2k4jh{i}asdkjh2.tunnel.example.com")
        for i in range(30)
    ]
    alerts = detect_dns_tunneling(records)
    assert len(alerts) == 1
    # detector groups by root registrable domain (last two labels), which is
    # correct behavior -- a tunneling C2 uses one domain with many random
    # subdomains, so alerts should key off "example.com", not the subdomain.
    assert alerts[0].root_domain == "example.com"


def test_dns_tunneling_ignores_normal_dns():
    records = [
        make_record(index=i, timestamp=i, dns_query="www.google.com")
        for i in range(30)
    ]
    alerts = detect_dns_tunneling(records)
    assert alerts == []


def test_plaintext_creds_detects_form_password():
    records = [
        make_record(index=0, timestamp=0.0, src_ip="10.0.0.5", dst_ip="10.0.0.9",
                    payload_snippet="POST /login HTTP/1.1\r\nuser=bob&password=hunter2")
    ]
    alerts = detect_plaintext_creds(records)
    assert len(alerts) >= 1
    assert any(a.kind == "form_password" for a in alerts)
