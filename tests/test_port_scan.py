"""
Tests for src/detections/port_scan.py

Covers detect_port_scan (unique-port threshold detection) and
correlate_scan_alerts (merging raw alerts into incidents).
"""

from datetime import datetime, timedelta, timezone

from src.detections.port_scan import (
    PortScanAlert,
    correlate_scan_alerts,
    detect_port_scan,
)
from src.parsers.ufw_parser import PortProbe


def make_probe(seconds_offset: float, dest_port: int, ip: str = "10.0.0.1") -> PortProbe:
    """Helper: build a PortProbe at a given offset from a fixed base time."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return PortProbe(
        timestamp=base + timedelta(seconds=seconds_offset),
        source_ip=ip,
        dest_ip="10.0.0.99",
        protocol="TCP",
        source_port=12345,
        dest_port=dest_port,
    )


def make_scan_alert(start_offset: int, end_offset: int, ports: set[int], ip: str = "10.0.0.1") -> PortScanAlert:
    """Helper: build a PortScanAlert directly, for testing correlate_scan_alerts in isolation."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return PortScanAlert(
        source_ip=ip,
        start_time=base + timedelta(seconds=start_offset),
        end_time=base + timedelta(seconds=end_offset),
        probe_count=len(ports),
        unique_ports=ports,
    )


# --- detect_port_scan tests ---

def test_detects_scan_above_threshold():
    # 8 different ports, all within 1 second: a clear scan burst
    probes = [make_probe(i * 0.1, dest_port=1000 + i) for i in range(8)]
    alerts = detect_port_scan(probes, threshold=8, window_seconds=10)

    assert len(alerts) == 1
    assert len(alerts[0].unique_ports) == 8
    assert alerts[0].source_ip == "10.0.0.1"


def test_no_alert_below_threshold():
    # only 7 unique ports, one short of the threshold
    probes = [make_probe(i * 0.1, dest_port=1000 + i) for i in range(7)]
    alerts = detect_port_scan(probes, threshold=8, window_seconds=10)

    assert len(alerts) == 0


def test_no_alert_when_probes_spread_outside_window():
    # 8 different ports, but 20 seconds apart each, never 8 within any 10s window
    probes = [make_probe(i * 20, dest_port=1000 + i) for i in range(8)]
    alerts = detect_port_scan(probes, threshold=8, window_seconds=10)

    assert len(alerts) == 0


def test_repeated_hits_on_same_port_do_not_count_as_scan():
    # 10 probes, but all against the SAME port: this is not a scan,
    # it's repetition. detect_port_scan should not flag this.
    probes = [make_probe(i * 0.1, dest_port=22) for i in range(10)]
    alerts = detect_port_scan(probes, threshold=8, window_seconds=10)

    assert len(alerts) == 0


# --- correlate_scan_alerts tests ---

def test_merges_close_scan_alerts_into_one_incident():
    alert1 = make_scan_alert(start_offset=0, end_offset=2, ports={1, 2, 3, 4, 5, 6, 7, 8})
    alert2 = make_scan_alert(start_offset=10, end_offset=12, ports={9, 10, 11, 12, 13, 14, 15, 16})

    merged = correlate_scan_alerts([alert1, alert2], merge_gap_seconds=30)

    assert len(merged) == 1
    assert len(merged[0].unique_ports) == 16  # all ports combined
    assert merged[0].start_time == alert1.start_time
    assert merged[0].end_time == alert2.end_time


def test_does_not_merge_distant_scan_alerts():
    alert1 = make_scan_alert(start_offset=0, end_offset=2, ports={1, 2, 3, 4, 5, 6, 7, 8})
    alert2 = make_scan_alert(start_offset=100, end_offset=102, ports={9, 10, 11, 12, 13, 14, 15, 16})

    merged = correlate_scan_alerts([alert1, alert2], merge_gap_seconds=30)

    assert len(merged) == 2


def test_does_not_merge_different_source_ips():
    alert1 = make_scan_alert(start_offset=0, end_offset=2, ports={1, 2, 3}, ip="10.0.0.1")
    alert2 = make_scan_alert(start_offset=5, end_offset=7, ports={4, 5, 6}, ip="10.0.0.2")

    merged = correlate_scan_alerts([alert1, alert2], merge_gap_seconds=30)

    assert len(merged) == 2


def test_empty_input_returns_empty_list():
    assert correlate_scan_alerts([]) == []


def test_single_alert_passes_through_unchanged():
    alert = make_scan_alert(start_offset=0, end_offset=2, ports={1, 2, 3})
    merged = correlate_scan_alerts([alert])

    assert len(merged) == 1
    assert merged[0] == alert