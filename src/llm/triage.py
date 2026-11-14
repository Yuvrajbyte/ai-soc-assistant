"""
LLM-based alert triage.

Takes a detection alert (from ssh_bruteforce.py or port_scan.py),
looks up the relevant MITRE ATT&CK technique from our local knowledge
base, and asks a local LLM (via Ollama) to produce a plain-English
summary and next steps for a human analyst.

Uses a local model (Ollama/llama3.2) rather than a cloud API, so no
log data leaves the machine, a deliberate choice for a security tool.
"""

import json
from dataclasses import dataclass

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2"


def load_knowledge_base(path: str = "src/llm/attack_kb/techniques.json") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@dataclass
class TriageResult:
    alert_type: str
    technique_id: str
    technique_name: str
    tactic: str
    summary: str
    recommended_response: list[str]


def build_prompt(alert_type: str, alert_str: str, technique_info: dict) -> str:
    """Construct the prompt given to the LLM, grounded in our ATT&CK knowledge base entry."""
    return f"""You are a security analyst assistant. Summarize the following detected alert in 2-3 plain-English sentences for someone who may not be deeply technical. Be factual and concise, do not invent details not present in the alert.

ALERT TYPE: {alert_type}
ALERT DETAILS: {alert_str}

RELEVANT MITRE ATT&CK TECHNIQUE:
ID: {technique_info['technique_id']}
Name: {technique_info['technique_name']}
Tactic: {technique_info['tactic']}
Description: {technique_info['description']}

Write only the plain-English summary, nothing else."""


def call_llm(prompt: str) -> str:
    response = requests.post(
        OLLAMA_URL,
        json={"model": MODEL_NAME, "prompt": prompt, "stream": False},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()["response"].strip()


def triage_alert(alert_type: str, alert_str: str) -> TriageResult:
    """
    alert_type: "ssh_bruteforce" or "port_scan", matching keys in the
    knowledge base.
    alert_str: the str() representation of a BruteForceAlert or
    PortScanAlert, e.g. from your existing detectors.
    """
    kb = load_knowledge_base()
    if alert_type not in kb:
        raise ValueError(f"Unknown alert type: {alert_type}. Known types: {list(kb.keys())}")

    technique_info = kb[alert_type]
    prompt = build_prompt(alert_type, alert_str, technique_info)
    summary = call_llm(prompt)

    return TriageResult(
        alert_type=alert_type,
        technique_id=technique_info["technique_id"],
        technique_name=technique_info["technique_name"],
        tactic=technique_info["tactic"],
        summary=summary,
        recommended_response=technique_info["recommended_response"],
    )


if __name__ == "__main__":
    # Quick manual test using a realistic SSH brute-force alert string,
    # matching the format your ssh_bruteforce.py's BruteForceAlert.__str__ produces.
    sample_alert = (
        "SSH brute force from 192.168.56.101: 45 failed attempts in 40.5s "
        "(targeting: labuser) [2026-11-05 20:14:32 -> 2026-11-05 20:15:13]"
    )

    result = triage_alert("ssh_bruteforce", sample_alert)

    print(f"Technique: {result.technique_id} - {result.technique_name} ({result.tactic})\n")
    print(f"Summary:\n{result.summary}\n")
    print("Recommended response:")
    for step in result.recommended_response:
        print(f"  - {step}")