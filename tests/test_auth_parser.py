"""
Tests for src/parsers/auth_parser.py

Uses real lines copied from our lab's auth.log as fixtures, so these
tests stay grounded in actual log formats rather than made-up examples.
"""

from datetime import datetime, timezone

from src.parsers.auth_parser import parse_line, LoginAttempt


def test_parses_failed_password_line():
    line = (
        "2026-11-05T20:14:32.618348+00:00 ubuntu-victim sshd-session[2769]: "
        "Failed password for labuser from 192.168.56.101 port 40564 ssh2"
    )
    result = parse_line(line)

    assert result is not None
    assert result.outcome == "Failed"
    assert result.username == "labuser"
    assert result.source_ip == "192.168.56.101"
    assert result.port == 40564
    assert result.timestamp == datetime(
        2026, 11, 5, 20, 14, 32, 618348, tzinfo=timezone.utc
    )


def test_parses_accepted_password_line():
    line = (
        "2026-11-05T20:15:11.188357+00:00 ubuntu-victim sshd-session[2798]: "
        "Accepted password for labuser from 192.168.56.101 port 52656 ssh2"
    )
    result = parse_line(line)

    assert result is not None
    assert result.outcome == "Accepted"
    assert result.username == "labuser"
    assert result.source_ip == "192.168.56.101"
    assert result.port == 52656


def test_ignores_unrelated_sudo_line():
    line = (
        "2026-11-05T20:18:20.198028+00:00 ubuntu-victim sudo: "
        "pam_unix(sudo:session): session opened for user root(uid=0) by labuser(uid=1000)"
    )
    result = parse_line(line)

    assert result is None


def test_ignores_unix_chkpwd_line():
    line = (
        "2026-11-05T20:14:30.724410+00:00 ubuntu-victim unix_chkpwd[2776]: "
        "password check failed for user (labuser)"
    )
    result = parse_line(line)

    assert result is None


def test_ignores_pam_max_retries_line():
    line = (
        "2026-11-05T20:14:50.166379+00:00 ubuntu-victim sshd-session[2768]: "
        "PAM service(sshd) ignoring max retries; 6 > 3"
    )
    result = parse_line(line)

    assert result is None


def test_ignores_blank_line():
    assert parse_line("") is None
    assert parse_line("\n") is None