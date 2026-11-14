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
- Documents what didn't work as carefully as what did (see "What i
  learned" below)
- Is designed to keep growing: ML anomaly detection, LLM-based triage,
  and prompt-injection testing are all planned next stages

## Architecture
## Architecture

```
Kali (attacker)
  |
  |--SSH brute force--> Ubuntu Server (victim) --> /var/log/auth.log
  |                                                        |
  |                                          src/parsers/auth_parser.py
  |                                        (regex -> structured LoginAttempt)
  |                                                        |
  |                                       src/detections/ssh_bruteforce.py
  |                                   (sliding-window threshold -> correlated incidents)
  |
  |--port scan (nmap)--> Ubuntu Server (victim) --> /var/log/ufw.log
                                                             |
                                               src/parsers/ufw_parser.py
                                          (regex -> structured PortProbe)
                                                             |
                                             src/detections/port_scan.py
                                     (unique-port threshold -> correlated incidents)

                    [ both pipelines feed into: ]
                    [ next: ML anomaly detection, comparing both attack types ]
                    [ next: LLM triage + ATT&CK mapping ]
                    [ next: Streamlit dashboard ]
```


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


## What i learned (and got wrong first)

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

  - **Ground-truth timestamps are accurate to the second**, not the
  millisecond.** `lab/attack_log.csv` records attack start/end times
  rounded to the nearest second, but real log events have
  millisecond-level precision. As a result, a handful of events
  landing just after a recorded `end_time` (but within the same
  second) can be mislabeled as normal instead of attack when building
  the ML feature table. This affected 2 out of 56 labeled windows in
  our first feature extraction. We left this as a known limitation
  rather than padding the window artificially, since documenting the
  precision mismatch is more honest than silently smoothing over it.

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


## Second attack type: port scanning

To give the project more than one attack signature to detect (and
eventually more than one class for ML to learn), i added port scan
detection as a second, structurally different attack type.

### Log source: UFW firewall log

SSH brute force and port scanning don't share a log file. `auth.log`
only records authentication attempts, it has no visibility into raw
TCP connection attempts against closed or unexpected ports. To capture
port scans, i enabled Ubuntu's UFW firewall with logging turned on
(`sudo ufw logging on`), which writes blocked connection attempts to
`/var/log/ufw.log` in a completely different format from auth.log.

This meant building a second parser, `src/parsers/ufw_parser.py`,
extracting `PortProbe` records (timestamp, source/destination IP,
protocol, source/destination port) via regex, following the same
validate-against-an-independent-count approach as the SSH parser.

### Detection: a different signal entirely

SSH brute force and port scanning look nothing alike in the data, which
is exactly why having two attack types matters for this project:

- **SSH brute force** is about **repetition**: many failed attempts
  against the *same* port and account, sustained over tens of seconds
  to minutes.
- **Port scanning** is about **breadth**: many *different* destination
  ports probed from one source IP, often within a fraction of a
  second.

`src/detections/port_scan.py` reflects this: instead of counting total
failed attempts like the SSH detector, it counts **unique destination
ports** within a sliding window (8+ unique ports within 10 seconds).
A test (`test_repeated_hits_on_same_port_do_not_count_as_scan`)
specifically locks in this distinction, confirming that repeated hits
on one port are correctly *not* flagged as a scan, that pattern
belongs to the brute-force detector instead.

### Results against real lab data

Two nmap scan sessions (`nmap -sS`, `-p-`, `-sV`, run a day apart)
produced 37 total logged probe events. The detector correctly
identified both as separate incidents:

| Metric | Value |
|---|---|
| Total probes parsed | 37 |
| Raw threshold alerts | 2 |
| Correlated incidents | 2 |
| Matches ground truth (`lab/attack_log.csv`)? | Yes, both sessions |

### Two unexpected findings worth noting

**1. Log volume doesn't scale linearly with attack scope.** A `-p-`
scan probes all 65,535 TCP ports, yet each session only generated
18-19 log lines, not tens of thousands. This is because UFW's logging
behavior and nmap's own scan optimizations mean most "filtered" ports
never generate an individually logged packet; only a representative
subset does. This matters for detection design: a threshold tuned by
assuming "more ports scanned = more log lines" would be miscalibrated
against real firewall logging behavior.

**2. The two attack types have very different time signatures.** SSH
brute-force incidents spanned tens of seconds to minutes (sustained,
repeated attempts). Port scan incidents were detected with a reported
duration of effectively 0.0 seconds, all 8+ ports were hit within the
same sub-second burst. This contrast (sustained repetition vs.
near-instantaneous breadth) is a strong candidate feature for the
upcoming ML stage: "time span of the incident" alone could help
distinguish attack types without needing to know the specific ports
or usernames involved.

### Tests

9 tests in `tests/test_port_scan.py`, covering threshold detection,
the same-port-is-not-a-scan distinction, and correlation logic
(merging nearby alerts, not merging across source IPs). Combined with
the SSH test suite, the project has **24 passing tests** total.

- **Almost lost labeled attack data to an overwrite.** Re-running scp
  to pull "fresh" logs for normal-traffic baselining nearly overwrote
  the original Nov 5 attack data with new (unrelated) log content from
  a VM reboot. Recovered via git history, since the data had been
  committed earlier. This reinforced that in this project, log files
  aren't just code assets, they're irreplaceable experimental results
  (exact attack timing/randomness can't be perfectly reproduced), so
  version control matters here as much as it does for code.

  ## ML vs. rule-based detection: an honest comparison

| Detector | Precision | Recall | Notes |
|---|---|---|---|
| Rule-based (SSH + port scan) | 100% | 100% | Validated against ground truth on both attack types |
| Isolation Forest | 75% | 55% | Trained on 76 windowed samples, evaluated on 23 held-out |

The rule-based detectors outperformed the ML model on this dataset,
and i think that's the right takeaway rather than a failure: domain-
specific rules (exact thresholds tuned to known attack signatures)
beat a generic unsupervised model when the dataset is small and the
attack patterns are well-understood. Isolation Forest's value would
likely grow with (a) a much larger and more varied dataset, and (b)
novel attack types the rules weren't explicitly written for, which is
exactly the gap ML is meant to fill in a real SOC: catching what rules
miss, not replacing well-understood detections.

## ML vs. rule-based detection: a three-way comparison

| Detector | Precision | Recall | Notes |
|---|---|---|---|
| Rule-based (SSH + port scan) | 100% | 100% | Hand-tuned thresholds, validated against all known attacks |
| Isolation Forest (unsupervised) | 83% | 83% | Trained on 97 windowed samples (59 normal / 38 attack), no labels used during training |
| Random Forest (supervised) | 86% | 100% | Same dataset, but trained with access to ground-truth labels |

**Takeaways:**

- **Rule-based detection remains the strongest performer** for these
  two specific, well-understood attack types. This makes sense: the
  rules encode exact domain knowledge (failure thresholds, port
  diversity) tuned directly to the attack signatures we generated.
  ML's value proposition isn't beating a good rule on a known
  pattern, it's generalizing to patterns nobody wrote a rule for yet.

- **More training data measurably improved the unsupervised model.**
  Isolation Forest's recall rose from 55% to 83% simply by growing the
  normal-traffic dataset from 38 to 59 samples, demonstrating that
  anomaly detection is highly data-hungry even on a simple task.

- **Giving the model labels (supervised Random Forest) closed most of
  the remaining gap**, reaching 100% recall. Its feature importances
  show `accepted_ssh_attempts` as the single most informative feature,
  more so than `failed_ssh_attempts`. On reflection this makes sense:
  our attack windows are characterized by an *absence* of successful
  logins just as much as a presence of failures, so the model learned
  both directions of the signal.

- **Caveat on the 100% recall figure:** with a test set of only 12
  attack samples (out of 97 total examples), this result should be
  read as promising rather than conclusive. A larger, more varied
  dataset (more sessions, more attack types, more normal-traffic
  baseline) would be needed before trusting this number in anything
  resembling production.