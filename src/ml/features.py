"""
Feature engineering for ML-based anomaly detection.

Buckets raw SSH login attempts and port probes into fixed-size time
windows per source IP, then computes numeric features per window.
Labels each window as attack (1) or normal (0) using lab/attack_log.csv
as ground truth, so we can measure the model honestly instead of just
eyeballing its output.

Deliberately excludes IP identity as a feature: the point of anomaly
detection is to learn from *behavior* (failure rates, port diversity,
timing), not to memorize which specific IPs were bad in this lab.
"""

import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from src.parsers.auth_parser import LoginAttempt, parse_log_file as parse_auth_log
from src.parsers.ufw_parser import PortProbe, parse_log_file as parse_ufw_log


@dataclass
class AttackWindow:
    start: datetime
    end: datetime


def load_attack_windows(path: str) -> list[AttackWindow]:
    """Load ground-truth attack time ranges from lab/attack_log.csv."""
    windows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            start = datetime.strptime(row["start_time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            end = datetime.strptime(row["end_time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            windows.append(AttackWindow(start=start, end=end))
    return windows


def is_attack_time(timestamp: datetime, attack_windows: list[AttackWindow]) -> bool:
    """Check whether a timestamp falls inside any known attack window."""
    # Normalize to UTC for comparison, since our logs mix UTC and IST timestamps.
    ts_utc = timestamp.astimezone(timezone.utc)
    return any(w.start <= ts_utc <= w.end for w in attack_windows)


def build_feature_table(
    attempts: list[LoginAttempt],
    probes: list[PortProbe],
    attack_windows: list[AttackWindow],
    window_seconds: int = 10,
) -> list[dict]:
    """
    Bucket attempts and probes into (source_ip, time_window) buckets
    and compute features for each. Returns a list of dicts, one per
    non-empty bucket, each labeled 1 (attack) or 0 (normal).
    """
    buckets: dict[tuple[str, int], dict] = defaultdict(lambda: {
        "failed_ssh": 0,
        "accepted_ssh": 0,
        "usernames": set(),
        "dest_ports": set(),
        "timestamps": [],
    })

    # Bucket key: (source_ip, window_index), where window_index groups
    # events into fixed-size slices of time since the Unix epoch.
    def window_index(ts: datetime) -> int:
        return int(ts.astimezone(timezone.utc).timestamp() // window_seconds)

    for attempt in attempts:
        key = (attempt.source_ip, window_index(attempt.timestamp))
        bucket = buckets[key]
        if attempt.outcome == "Failed":
            bucket["failed_ssh"] += 1
        else:
            bucket["accepted_ssh"] += 1
        bucket["usernames"].add(attempt.username)
        bucket["timestamps"].append(attempt.timestamp)

    for probe in probes:
        key = (probe.source_ip, window_index(probe.timestamp))
        bucket = buckets[key]
        bucket["dest_ports"].add(probe.dest_port)
        bucket["timestamps"].append(probe.timestamp)

    rows = []
    for (source_ip, _), bucket in buckets.items():
        timestamps = bucket["timestamps"]
        span = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0.0
        representative_ts = min(timestamps)  # use window start for labeling

        rows.append({
            "source_ip": source_ip,
            "window_start": representative_ts,
            "failed_ssh_attempts": bucket["failed_ssh"],
            "accepted_ssh_attempts": bucket["accepted_ssh"],
            "unique_usernames": len(bucket["usernames"]),
            "unique_dest_ports": len(bucket["dest_ports"]),
            "total_events": bucket["failed_ssh"] + bucket["accepted_ssh"] + len(bucket["dest_ports"]),
            "window_span_seconds": span,
            "label": int(is_attack_time(representative_ts, attack_windows)),
        })

    return rows


if __name__ == "__main__":
    attempts = parse_auth_log("data/raw/auth.log") + parse_auth_log("data/raw/auth_normal.log")
    probes = parse_ufw_log("data/raw/ufw.log")
    attack_windows = load_attack_windows("lab/attack_log.csv")

    rows = build_feature_table(attempts, probes, attack_windows, window_seconds=10)

    attack_rows = [r for r in rows if r["label"] == 1]
    normal_rows = [r for r in rows if r["label"] == 0]

    print(f"Total windows: {len(rows)}")
    print(f"Attack windows: {len(attack_rows)}")
    print(f"Normal windows: {len(normal_rows)}\n")

    print("Sample attack window:")
    print(attack_rows[0] if attack_rows else "(none)")
    print("\nSample normal window:")
    print(normal_rows[0] if normal_rows else "(none)")

    # Save as CSV for the training script to consume.
    import os
    os.makedirs("data/labeled", exist_ok=True)
    with open("data/labeled/features.csv", "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "source_ip", "window_start", "failed_ssh_attempts",
            "accepted_ssh_attempts", "unique_usernames", "unique_dest_ports",
            "total_events", "window_span_seconds", "label",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nSaved {len(rows)} rows to data/labeled/features.csv")