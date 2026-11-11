# AI SOC Assistant

An AI-powered Security Operations Center (SOC) assistant that ingests
real SSH authentication logs, detects brute-force attacks using both
rule-based and (upcoming) ML-based detection, and will eventually use
an LLM to triage alerts and map them to MITRE ATT&CK techniques.

Built against **real attack data** generated in a self-hosted lab
(Kali Linux attacking an Ubuntu Server victim over SSH), not a
downloaded dataset like NSL-KDD. Every number in this README comes
from logs the attacks in this repo actually produced.

## Why this project

Most "AI + cybersecurity" student projects train a classifier on an
outdated public dataset and call it done. This project instead:
- Generates its own labeled attack data from a real, isolated VM lab
- Builds detection the way security teams actually do: rules first,
  then ML as a comparison layer, not a replacement
- Documents what didn't work as carefully as what did (see "What we
  learned" below)
- Is designed to keep growing: ML anomaly detection, LLM-based triage,
  and prompt-injection testing are all planned next stages

## Architecture
Kali (attacker) --SSH brute force--> Ubuntu Server (victim)
|
/var/log/auth.log
|
src/parsers/auth_parser.py
(regex -> structured LoginAttempt)
|
src/detections/ssh_bruteforce.py
(sliding-window threshold -> correlated incidents)
|
[ next: ML anomaly detection ]
[ next: LLM triage + ATT&CK mapping ]
[ next: Streamlit dashboard ]


## Lab setup

- **Attacker:** Kali Linux (VirtualBox)
- **Victim:** Ubuntu Server 24.04 LTS, OpenSSH enabled
- **Network:** VirtualBox host-only adapter, fully isolated from the
  internet and home network
- **Attack tool:** Hydra (SSH password brute-force)

Full setup steps are in [`lab/setup.md`](lab/setup.md). Attack
timestamps and outcomes are logged in
[`lab/attack_log.csv`](lab/attack_log.csv) as ground truth for
validating detection accuracy.

## What's built so far

### 1. Log parser (`src/parsers/auth_parser.py`)
Parses raw `auth.log` lines into structured `LoginAttempt` objects
(timestamp, username, source IP, port, outcome) using regex with named
capture groups. Verified against an independent line count
(`Select-String`/`grep`): parser and manual count agree exactly
(204 failed attempts, 6 accepted).

### 2. Rule-based detection (`src/detections/ssh_bruteforce.py`)
A sliding-window threshold detector: flags any source IP with 5+
failed logins within any 60-second window. Ran against real lab data
with **zero false positives**.

### 3. Alert correlation
See below — merges repeated threshold alerts from a sustained attack
into a single incident, closer to how a real SOC would see it.

[... paste the existing "Detection: raw alerts vs. correlated
incidents" section here, unchanged ...]

## Testing

15 automated tests across two files (`pytest`):
- `tests/test_auth_parser.py` (6 tests) — parser correctness, including
  negative cases (confirms noise lines like `sudo`/`CRON` are ignored)
- `tests/test_ssh_bruteforce.py` (9 tests) — threshold detection and
  correlation logic, using synthetic timestamps for precise control
  over edge cases (e.g. attempts spread outside the time window,
  alerts from different source IPs that shouldn't be merged)

Run with:
pytest -v


## What we learned (and got wrong first)

- **Clock/timezone confusion early on:** Kali and Ubuntu initially
  displayed different timezones, making it look like a third attack
  had happened when it hadn't. Fixed by standardizing both VMs to the
  same timezone and, more importantly, learning to always read ground
  truth from the log file's own timestamps rather than trusting a
  tool's printed output.
- **Raw threshold alerts don't equal real incidents** (see detection
  section above) — a core finding about why correlation layers exist
  in real SIEM tools.
- **venv paths break on folder moves** — moving the project directory
  after creating a virtual environment broke `pip`, since venvs
  hardcode absolute paths. Fixed by recreating the venv after moving
  the project to its permanent location.

## Roadmap

- [ ] ML anomaly detection (Isolation Forest), compared honestly
      against the rule-based detector's precision/recall
- [ ] LLM-based alert triage: plain-English summaries + MITRE ATT&CK
      technique mapping via RAG
- [ ] Streamlit dashboard for browsing incidents
- [ ] Additional attack types (port scanning, web attacks via
      DVWA/Juice Shop) for broader detection coverage
- [ ] Prompt-injection testing against the LLM triage layer (can a
      malicious log line hijack the summarizer?)

## Tech stack

Python, pandas, scikit-learn (planned), pytest, FastAPI (planned),
Streamlit (planned), VirtualBox, Kali Linux, Ubuntu Server, Hydra