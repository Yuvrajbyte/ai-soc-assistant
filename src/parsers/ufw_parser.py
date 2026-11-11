"""
Parser for Ubuntu's UFW firewall log (/var/log/ufw.log).

Extracts structured port-scan probe events (timestamp, source IP,
destination IP, destination port, protocol) from UFW BLOCK lines.
Each line represents one blocked connection attempt, typically one
per port probed during an nmap scan.
"""

import re
from dataclasses import dataclass
from datetime import datetime


# Matches lines like:
# 2026-11-11T00:44:12.682490+05:30 ubuntu-victim kernel: [UFW BLOCK] IN=enp0s3 OUT= MAC=... SRC=192.168.56.101 DST=192.168.56.10 LEN=44 TOS=0x00 PREC=0x00 TTL=56 ID=65251 PROTO=TCP SPT=44881 DPT=995 WINDOW=1024 RES=0x00 SYN URGP=0
UFW_BLOCK_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"kernel:\s+\[UFW BLOCK\]\s+"
    r".*?"                                   # skip IN=, OUT=, MAC= fields, we don't need them
    r"SRC=(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"DST=(?P<dest_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r".*?"                                   # skip LEN=, TOS=, PREC=, TTL=, ID=
    r"PROTO=(?P<protocol>\S+)\s+"
    r"SPT=(?P<source_port>\d+)\s+"
    r"DPT=(?P<dest_port>\d+)"
)


@dataclass
class PortProbe:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    source_port: int
    dest_port: int


def parse_line(line: str) -> PortProbe | None:
    """Parse a single ufw.log line. Returns None if it's not a UFW BLOCK line."""
    match = UFW_BLOCK_PATTERN.search(line)
    if not match:
        return None

    return PortProbe(
        timestamp=datetime.fromisoformat(match.group("timestamp")),
        source_ip=match.group("source_ip"),
        dest_ip=match.group("dest_ip"),
        protocol=match.group("protocol"),
        source_port=int(match.group("source_port")),
        dest_port=int(match.group("dest_port")),
    )


def parse_log_file(path: str) -> list[PortProbe]:
    """Parse an entire ufw.log file and return all blocked probe events found."""
    probes = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            probe = parse_line(line)
            if probe is not None:
                probes.append(probe)
    return probes


if __name__ == "__main__":
    import sys

    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/ufw.log"
    results = parse_log_file(log_path)

    print(f"Parsed {len(results)} blocked probes from {log_path}\n")
    for probe in results[:10]:
        print(probe)

    unique_ports = {p.dest_port for p in results}
    unique_ips = {p.source_ip for p in results}
    print(f"\nUnique source IPs: {unique_ips}")
    print(f"Unique destination ports probed: {len(unique_ports)}")