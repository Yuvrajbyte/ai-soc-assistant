"""
Parser for Ubuntu /var/log/auth.log (sshd-session lines).

Extracts structured login attempts (timestamp, username, source IP,
port, outcome) from raw syslog lines. Ignores unrelated lines
(sudo, CRON, systemd-logind, PAM noise, etc.) for now.
"""

import re
from dataclasses import dataclass
from datetime import datetime


# Matches lines like:
# 2026-11-05T15:10:49.555610+00:00 ubuntu-victim sshd-session[2804]: Failed password for labuser from 192.168.56.101 port 52656
# 2026-11-05T15:11:18.187100+00:00 ubuntu-victim sshd-session[2798]: Accepted password for labuser from 192.168.56.101 port 52660
SSH_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"          # ISO timestamp, e.g. 2026-11-05T15:10:49.555610+00:00
    r"(?P<host>\S+)\s+"                # hostname, e.g. ubuntu-victim
    r"sshd-session\[\d+\]:\s+"         # process name + pid, e.g. sshd-session[2804]:
    r"(?P<outcome>Failed|Accepted)\s+password\s+"
    r"for\s+(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"port\s+(?P<port>\d+)"
)


@dataclass
class LoginAttempt:
    timestamp: datetime
    username: str
    source_ip: str
    port: int
    outcome: str  # "Failed" or "Accepted"


def parse_line(line: str) -> LoginAttempt | None:
    """Parse a single auth.log line. Returns None if it's not a login attempt line."""
    match = SSH_LOGIN_PATTERN.search(line)
    if not match:
        return None

    return LoginAttempt(
        timestamp=datetime.fromisoformat(match.group("timestamp")),
        username=match.group("username"),
        source_ip=match.group("source_ip"),
        port=int(match.group("port")),
        outcome=match.group("outcome"),
    )


def parse_log_file(path: str) -> list[LoginAttempt]:
    """Parse an entire auth.log file and return all login attempts found."""
    attempts = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            attempt = parse_line(line)
            if attempt is not None:
                attempts.append(attempt)
    return attempts


if __name__ == "__main__":
    import sys

    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/auth.log"
    results = parse_log_file(log_path)

    print(f"Parsed {len(results)} login attempts from {log_path}\n")
    for attempt in results[:10]:
        print(attempt)

    failed = sum(1 for a in results if a.outcome == "Failed")
    accepted = sum(1 for a in results if a.outcome == "Accepted")
    print(f"\nFailed: {failed}, Accepted: {accepted}")