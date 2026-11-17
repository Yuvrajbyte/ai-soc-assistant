"""
Parser for Juice Shop's Docker logs (captured via `docker logs --timestamps`).

Juice Shop doesn't log structured HTTP access logs by default; instead,
unmatched routes produce an "Unexpected path" error with a full stack
trace. We only care about the one line naming the attempted path, the
stack trace lines beneath it are noise, similar to auth.log's
PAM/unix_chkpwd noise around the lines we actually want.
"""

import re
from dataclasses import dataclass
from datetime import datetime


# Matches lines like:
# 2026-11-15T20:01:07.674922812Z Error: Unexpected path: /restored
UNEXPECTED_PATH_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"Error:\s+Unexpected path:\s+(?P<path>\S+)"
)


@dataclass
class PathProbe:
    timestamp: datetime
    path: str


def _parse_docker_timestamp(raw: str) -> datetime:
    """
    Docker's --timestamps can emit more fractional-second digits than
    Python's datetime supports (max 6, microseconds). Truncate to 6
    digits before parsing, trimming extra precision we don't need.
    """
    raw = raw.rstrip("Z") + "+00:00"
    if "." in raw:
        base, frac_and_offset = raw.split(".", 1)
        frac_digits = ""
        i = 0
        while i < len(frac_and_offset) and frac_and_offset[i].isdigit():
            frac_digits += frac_and_offset[i]
            i += 1
        rest = frac_and_offset[i:]
        frac_digits = frac_digits[:6].ljust(6, "0")  # pad/truncate to exactly 6 digits
        raw = f"{base}.{frac_digits}{rest}"
    return datetime.fromisoformat(raw)


def parse_line(line: str) -> PathProbe | None:
    """Parse a single Docker log line. Returns None if it's not an 'Unexpected path' line."""
    match = UNEXPECTED_PATH_PATTERN.search(line)
    if not match:
        return None

    return PathProbe(
        timestamp=_parse_docker_timestamp(match.group("timestamp")),
        path=match.group("path"),
    )


def parse_log_file(path: str) -> list[PathProbe]:
    """Parse an entire Juice Shop docker log file and return all path probes found."""
    probes = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            probe = parse_line(line)
            if probe is not None:
                probes.append(probe)
    return probes


if __name__ == "__main__":
    import sys

    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/raw/juiceshop.log"
    results = parse_log_file(log_path)

    print(f"Parsed {len(results)} unexpected-path probes from {log_path}\n")
    for probe in results[:10]:
        print(probe)

    unique_paths = {p.path for p in results}
    print(f"\nUnique paths probed: {len(unique_paths)}")