"""
Rule-based SSH brute-force detector.

Takes parsed LoginAttempt objects and flags source IPs that generate
too many failed logins in too short a time window. This is the
"detection engineering" layer: it doesn't need ML to catch a Hydra-style
attack, a simple threshold rule does the job and gives you a baseline
to compare future ML models against.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from src.parsers.auth_parser import LoginAttempt


@dataclass
class BruteForceAlert:
    source_ip: str
    start_time: datetime
    end_time: datetime
    attempt_count: int
    usernames_targeted: set[str] = field(default_factory=set)

    def __str__(self) -> str:
        duration = (self.end_time - self.start_time).total_seconds()
        return (
            f"[ALERT] SSH brute force from {self.source_ip}: "
            f"{self.attempt_count} failed attempts in {duration:.1f}s "
            f"(targeting: {', '.join(sorted(self.usernames_targeted))}) "
            f"[{self.start_time} -> {self.end_time}]"
        )


def detect_bruteforce(
    attempts: list[LoginAttempt],
    threshold: int = 5,
    window_seconds: int = 60,
) -> list[BruteForceAlert]:
    """
    Flag source IPs with >= `threshold` failed login attempts within
    any `window_seconds` sliding window.

    Returns one alert per detected burst, not one alert per attempt,
    so a 50-attempt attack produces one alert, not fifty.
    """
    # Group failed attempts by source IP, keeping only Failed outcomes.
    by_ip: dict[str, list[LoginAttempt]] = defaultdict(list)
    for attempt in attempts:
        if attempt.outcome == "Failed":
            by_ip[attempt.source_ip].append(attempt)

    alerts = []

    for ip, ip_attempts in by_ip.items():
        ip_attempts.sort(key=lambda a: a.timestamp)

        window: deque[LoginAttempt] = deque()

        for attempt in ip_attempts:
            window.append(attempt)

            # Drop attempts that have fallen outside the time window.
            while (attempt.timestamp - window[0].timestamp).total_seconds() > window_seconds:
                window.popleft()

            # Threshold met: raise an alert and reset the window so we
            # don't fire a new alert on every single attempt afterward.
            if len(window) >= threshold:
                alerts.append(
                    BruteForceAlert(
                        source_ip=ip,
                        start_time=window[0].timestamp,
                        end_time=window[-1].timestamp,
                        attempt_count=len(window),
                        usernames_targeted={a.username for a in window},
                    )
                )
                window.clear()

    return alerts

def correlate_alerts(
    alerts: list[BruteForceAlert],
    merge_gap_seconds: int = 30,
) -> list[BruteForceAlert]:
    """
    Merge raw threshold alerts from the same source IP into fewer,
    larger incidents when they occur close together in time.

    Without this, one sustained brute-force run (which repeatedly
    crosses the detection threshold as it keeps attacking) produces
    dozens of near-duplicate alerts instead of one coherent incident.
    This mirrors how real SIEM/SOC tools correlate raw rule hits into
    a single incident for an analyst to review.
    """
    if not alerts:
        return []

    # Group by source IP first, since we only ever merge alerts
    # that came from the same attacker.
    by_ip: dict[str, list[BruteForceAlert]] = defaultdict(list)
    for alert in alerts:
        by_ip[alert.source_ip].append(alert)

    merged_alerts = []

    for ip, ip_alerts in by_ip.items():
        ip_alerts.sort(key=lambda a: a.start_time)

        current = ip_alerts[0]

        for next_alert in ip_alerts[1:]:
            gap = (next_alert.start_time - current.end_time).total_seconds()

            if gap <= merge_gap_seconds:
                # Close enough in time: treat as the same ongoing incident.
                current = BruteForceAlert(
                    source_ip=ip,
                    start_time=current.start_time,
                    end_time=next_alert.end_time,
                    attempt_count=current.attempt_count + next_alert.attempt_count,
                    usernames_targeted=current.usernames_targeted | next_alert.usernames_targeted,
                )
            else:
                # Gap too large: the current incident is done, start a new one.
                merged_alerts.append(current)
                current = next_alert

        merged_alerts.append(current)

    return merged_alerts


if __name__ == "__main__":
    import sys

    from src.parsers.auth_parser import parse_log_file

    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/auth.log"
    attempts = parse_log_file(log_path)
    raw_alerts = detect_bruteforce(attempts)
    incidents = correlate_alerts(raw_alerts)

    print(f"Parsed {len(attempts)} attempts")
    print(f"Raw threshold alerts: {len(raw_alerts)}")
    print(f"Correlated incidents: {len(incidents)}\n")

    for incident in incidents:
        print(incident)