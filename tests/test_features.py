"""
Tests for src/ml/features.py

Covers attack-window loading/matching and the feature-bucketing logic
that turns raw events into labeled windows for ML training.
"""

import csv
from datetime import datetime, timedelta, timezone

import pytest

from src.ml.features import (
    AttackWindow,
    build_feature_table,
    is_attack_time,
    load_attack_windows,
)
from src.parsers.auth_parser import LoginAttempt
from src.parsers.ufw_parser import PortProbe


def make_attempt(seconds_offset: int, outcome: str = "Failed", ip: str = "10.0.0.1") -> LoginAttempt:
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return LoginAttempt(
        timestamp=base + timedelta(seconds=seconds_offset),
        username="testuser",
        source_ip=ip,
        port=22,
        outcome=outcome,
    )


def make_probe(seconds_offset: int, dest_port: int, ip: str = "10.0.0.1") -> PortProbe:
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    return PortProbe(
        timestamp=base + timedelta(seconds=seconds_offset),
        source_ip=ip,
        dest_ip="10.0.0.99",
        protocol="TCP",
        source_port=12345,
        dest_port=dest_port,
    )


# --- load_attack_windows tests ---

def test_loads_attack_windows_from_csv(tmp_path):
    csv_path = tmp_path / "attack_log.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["start_time", "end_time", "tool", "technique", "target", "notes"])
        writer.writerow(["2026-01-01 00:00:00", "2026-01-01 00:01:00", "hydra", "ssh_bruteforce", "10.0.0.1", "test"])

    windows = load_attack_windows(str(csv_path))

    assert len(windows) == 1
    assert windows[0].start == datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert windows[0].end == datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc)


# --- is_attack_time tests ---

def test_timestamp_inside_window_is_attack():
    windows = [AttackWindow(
        start=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
    )]
    ts = datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc)

    assert is_attack_time(ts, windows) is True


def test_timestamp_outside_window_is_not_attack():
    windows = [AttackWindow(
        start=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
    )]
    ts = datetime(2026, 1, 1, 0, 5, 0, tzinfo=timezone.utc)

    assert is_attack_time(ts, windows) is False


def test_is_attack_time_handles_mixed_timezones():
    # Attack window stored in UTC; checked timestamp given in IST (+5:30).
    # The same real moment in both cases should still be recognized as
    # an attack, regardless of which timezone it's expressed in. This
    # guards against the exact bug we hit with attack_log.csv earlier.
    windows = [AttackWindow(
        start=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
    )]
    ist = timezone(timedelta(hours=5, minutes=30))
    ts_in_ist = datetime(2026, 1, 1, 5, 30, 30, tzinfo=ist)  # same instant as 00:00:30 UTC

    assert is_attack_time(ts_in_ist, windows) is True


# --- build_feature_table tests ---

def test_attack_window_labeled_correctly():
    attempts = [make_attempt(i) for i in range(5)]  # 5 failures, same IP
    windows = [AttackWindow(
        start=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        end=datetime(2026, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
    )]

    rows = build_feature_table(attempts, [], windows, window_seconds=10)

    assert len(rows) == 1
    assert rows[0]["label"] == 1
    assert rows[0]["failed_ssh_attempts"] == 5


def test_normal_window_labeled_correctly():
    attempts = [make_attempt(0, outcome="Accepted")]
    windows = []  # no known attacks at all

    rows = build_feature_table(attempts, [], windows, window_seconds=10)

    assert len(rows) == 1
    assert rows[0]["label"] == 0
    assert rows[0]["accepted_ssh_attempts"] == 1


def test_port_probes_counted_as_unique_dest_ports():
    probes = [make_probe(0, dest_port=22), make_probe(1, dest_port=80), make_probe(2, dest_port=443)]
    rows = build_feature_table([], probes, [], window_seconds=10)

    assert len(rows) == 1
    assert rows[0]["unique_dest_ports"] == 3


def test_different_source_ips_create_separate_buckets():
    attempts = [
        make_attempt(0, ip="10.0.0.1"),
        make_attempt(0, ip="10.0.0.2"),
    ]
    rows = build_feature_table(attempts, [], [], window_seconds=10)

    assert len(rows) == 2
    assert {r["source_ip"] for r in rows} == {"10.0.0.1", "10.0.0.2"}


def test_events_outside_window_create_separate_buckets():
    # Same IP, but 100 seconds apart: should land in different
    # 10-second buckets, not get merged into one.
    attempts = [make_attempt(0), make_attempt(100)]
    rows = build_feature_table(attempts, [], [], window_seconds=10)

    assert len(rows) == 2