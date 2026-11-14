"""
End-to-end: parse real logs, detect real incidents, triage each one
with the LLM. Ties together the parser, detector, and triage layers.
"""

from src.parsers.auth_parser import parse_log_file as parse_auth_log
from src.detections.ssh_bruteforce import detect_bruteforce, correlate_alerts
from src.llm.triage import triage_alert
from src.parsers.ufw_parser import parse_log_file as parse_ufw_log
from src.detections.port_scan import detect_port_scan, correlate_scan_alerts


if __name__ == "__main__":
    attempts = parse_auth_log("data/raw/auth.log")
    raw_alerts = detect_bruteforce(attempts)
    incidents = correlate_alerts(raw_alerts)

    print(f"Found {len(incidents)} SSH brute-force incident(s)\n")

    for i, incident in enumerate(incidents, 1):
        print(f"--- Incident {i} ---")
        print(str(incident))
        print()

        result = triage_alert("ssh_bruteforce", str(incident))
        print(f"MITRE ATT&CK: {result.technique_id} - {result.technique_name}")
        print(f"Summary: {result.summary}")
        print("Next steps:")
        for step in result.recommended_response:
            print(f"  - {step}")
        print()

    probes = parse_ufw_log("data/raw/ufw.log")
    raw_scan_alerts = detect_port_scan(probes)
    scan_incidents = correlate_scan_alerts(raw_scan_alerts)

    print(f"\nFound {len(scan_incidents)} port scan incident(s)\n")

    for i, incident in enumerate(scan_incidents, 1):
        print(f"--- Port Scan Incident {i} ---")
        print(str(incident))
        print()

        result = triage_alert("port_scan", str(incident))
        print(f"MITRE ATT&CK: {result.technique_id} - {result.technique_name}")
        print(f"Summary: {result.summary}")
        print("Next steps:")
        for step in result.recommended_response:
            print(f"  - {step}")
        print()