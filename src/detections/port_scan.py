"""
Rule-based port scan detector.

Takes parsed PortProbe objects and flags source IPs that probe many
*different* destination ports within a short time window. This is a
different signal from SSH brute force: there, we counted repeated
failures against one port/account. Here, we count breadth across
ports, the signature of reconnaissance (nmap-style scanning) rather
than a focused attack on one service.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from src.parsers.ufw_parser import PortProbe


@dataclass
class PortScanAlert:
    source_ip: str
    start_time: datetime
    end_time: datetime
    probe_count: int
    unique_ports: set[int] = field(default_factory=set)

    def __str__(self) -> str:
        duration = (self.end_time - self.start_time).total_seconds()
        return (
            f"[ALERT] Port scan from {self.source_ip}: "
            f"{len(self.unique_ports)} unique ports probed "
            f"({self.probe_count} total probes) in {duration:.1f}s "
            f"[{self.start_time} -> {self.end_time}]"
        )


def detect_port_scan(
    probes: list[PortProbe],
    threshold: int = 8,
    window_seconds: int = 10,
) -> list[PortScanAlert]:
    """
    Flag source IPs that probe >= `threshold` unique destination ports
    within any `window_seconds` sliding window.

    Unlike SSH brute force (which counts repeated failures), here we
    count *distinct* ports, since scanning many ports once each is the
    actual signature of reconnaissance, not repetition against one port.
    """
    by_ip: dict[str, list[PortProbe]] = defaultdict(list)
    for probe in probes:
        by_ip[probe.source_ip].append(probe)

    alerts = []

    for ip, ip_probes in by_ip.items():
        ip_probes.sort(key=lambda p: p.timestamp)

        window: deque[PortProbe] = deque()

        for probe in ip_probes:
            window.append(probe)

            while (probe.timestamp - window[0].timestamp).total_seconds() > window_seconds:
                window.popleft()

            unique_ports_in_window = {p.dest_port for p in window}

            if len(unique_ports_in_window) >= threshold:
                alerts.append(
                    PortScanAlert(
                        source_ip=ip,
                        start_time=window[0].timestamp,
                        end_time=window[-1].timestamp,
                        probe_count=len(window),
                        unique_ports=unique_ports_in_window,
                    )
                )
                window.clear()

    return alerts


def correlate_scan_alerts(
    alerts: list[PortScanAlert],
    merge_gap_seconds: int = 30,
) -> list[PortScanAlert]:
    """
    Merge raw port-scan alerts from the same source IP into fewer
    incidents when they occur close together in time. Same idea as
    correlate_alerts() in ssh_bruteforce.py: a single sustained scan
    can cross the threshold multiple times and shouldn't appear as
    multiple separate incidents.
    """
    if not alerts:
        return []

    by_ip: dict[str, list[PortScanAlert]] = defaultdict(list)
    for alert in alerts:
        by_ip[alert.source_ip].append(alert)

    merged_alerts = []

    for ip, ip_alerts in by_ip.items():
        ip_alerts.sort(key=lambda a: a.start_time)

        current = ip_alerts[0]

        for next_alert in ip_alerts[1:]:
            gap = (next_alert.start_time - current.end_time).total_seconds()

            if gap <= merge_gap_seconds:
                current = PortScanAlert(
                    source_ip=ip,
                    start_time=current.start_time,
                    end_time=next_alert.end_time,
                    probe_count=current.probe_count + next_alert.probe_count,
                    unique_ports=current.unique_ports | next_alert.unique_ports,
                )
            else:
                merged_alerts.append(current)
                current = next_alert

        merged_alerts.append(current)

    return merged_alerts


if __name__ == "__main__":
    import sys

    from src.parsers.ufw_parser import parse_log_file

    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/ufw.log"
    probes = parse_log_file(log_path)
    raw_alerts = detect_port_scan(probes)
    incidents = correlate_scan_alerts(raw_alerts)

    print(f"Parsed {len(probes)} probes")
    print(f"Raw threshold alerts: {len(raw_alerts)}")
    print(f"Correlated incidents: {len(incidents)}\n")

    for incident in incidents:
        print(incident)