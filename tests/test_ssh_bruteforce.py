"""
Tests for src/detections/ssh_bruteforce.py

Covers both detect_bruteforce (threshold detection) and
correlate_alerts (merging raw alerts into incidents).
"""

from datetime import datetime, timedelta, timezone

from src.detections.ssh_bruteforce import (
    BruteForceAlert,
    correlate_alerts,
    detect_bruteforce,
)
from src.parsers.auth_parser import LoginAttempt


def make_attempt(seconds_offset: int, outcome: str = "Failed", ip: str = "10.0.0.1") -> LoginAttempt:
    """Helper: build a LoginAttempt at a given offset from a fixed base time."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return LoginAttempt(
        timestamp=base + timedelta(seconds=seconds_offset),
        username="testuser",
        source_ip=ip,
        port=22,
        outcome=outcome,
    )


def make_alert(start_offset: int, end_offset: int, count: int = 5, ip: str = "10.0.0.1") -> BruteForceAlert:
    """Helper: build a BruteForceAlert directly, for testing correlate_alerts in isolation."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return BruteForceAlert(
        source_ip=ip,
        start_time=base + timedelta(seconds=start_offset),
        end_time=base + timedelta(seconds=end_offset),
        attempt_count=count,
        usernames_targeted={"testuser"},
    )


# --- detect_bruteforce tests ---

def test_detects_burst_above_threshold():
    attempts = [make_attempt(i) for i in range(5)]  # 5 failures, 1 second apart
    alerts = detect_bruteforce(attempts, threshold=5, window_seconds=60)

    assert len(alerts) == 1
    assert alerts[0].attempt_count == 5
    assert alerts[0].source_ip == "10.0.0.1"


def test_no_alert_below_threshold():
    attempts = [make_attempt(i) for i in range(4)]  # only 4 failures
    alerts = detect_bruteforce(attempts, threshold=5, window_seconds=60)

    assert len(alerts) == 0


def test_no_alert_when_attempts_spread_outside_window():
    # 5 failures, but 100 seconds apart each, never 5 within any 60s window
    attempts = [make_attempt(i * 100) for i in range(5)]
    alerts = detect_bruteforce(attempts, threshold=5, window_seconds=60)

    assert len(alerts) == 0


def test_accepted_attempts_are_ignored():
    attempts = [make_attempt(i, outcome="Accepted") for i in range(10)]
    alerts = detect_bruteforce(attempts, threshold=5, window_seconds=60)

    assert len(alerts) == 0


# --- correlate_alerts tests ---

def test_merges_close_alerts_into_one_incident():
    alert1 = make_alert(start_offset=0, end_offset=10)
    alert2 = make_alert(start_offset=15, end_offset=25)  # starts 5s after alert1 ends

    merged = correlate_alerts([alert1, alert2], merge_gap_seconds=30)

    assert len(merged) == 1
    assert merged[0].attempt_count == 10  # 5 + 5 combined
    assert merged[0].start_time == alert1.start_time
    assert merged[0].end_time == alert2.end_time


def test_does_not_merge_distant_alerts():
    alert1 = make_alert(start_offset=0, end_offset=10)
    alert2 = make_alert(start_offset=100, end_offset=110)  # 90s gap, too far

    merged = correlate_alerts([alert1, alert2], merge_gap_seconds=30)

    assert len(merged) == 2


def test_does_not_merge_different_source_ips():
    alert1 = make_alert(start_offset=0, end_offset=10, ip="10.0.0.1")
    alert2 = make_alert(start_offset=12, end_offset=20, ip="10.0.0.2")  # close in time, different IP

    merged = correlate_alerts([alert1, alert2], merge_gap_seconds=30)

    assert len(merged) == 2


def test_empty_input_returns_empty_list():
    assert correlate_alerts([]) == []


def test_single_alert_passes_through_unchanged():
    alert = make_alert(start_offset=0, end_offset=10)
    merged = correlate_alerts([alert])

    assert len(merged) == 1
    assert merged[0] == alert