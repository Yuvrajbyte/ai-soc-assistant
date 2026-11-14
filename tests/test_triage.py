"""
Tests for src/llm/triage.py

The actual LLM call (call_llm) is mocked throughout, so these tests
run instantly and don't require Ollama to be installed or running.
This also means CI or a reviewer's machine can run the full test
suite without any local model setup. What we DO test for real: the
knowledge base lookup, prompt construction, and that triage_alert
correctly assembles its result from deterministic (non-LLM) data.
"""

from unittest.mock import patch

import pytest

from src.llm.triage import (
    build_prompt,
    load_knowledge_base,
    triage_alert,
    TriageResult,
)


def test_knowledge_base_has_both_attack_types():
    kb = load_knowledge_base()
    assert "ssh_bruteforce" in kb
    assert "port_scan" in kb


def test_knowledge_base_entries_have_required_fields():
    kb = load_knowledge_base()
    required_fields = ["technique_id", "technique_name", "tactic", "description", "recommended_response"]

    for alert_type, entry in kb.items():
        for field in required_fields:
            assert field in entry, f"{alert_type} is missing field '{field}'"


def test_build_prompt_includes_alert_details():
    technique_info = {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "description": "Test description.",
    }
    prompt = build_prompt("ssh_bruteforce", "45 failed attempts from 10.0.0.1", technique_info)

    assert "45 failed attempts from 10.0.0.1" in prompt
    assert "T1110.001" in prompt
    assert "Brute Force: Password Guessing" in prompt


def test_build_prompt_instructs_against_fabrication():
    technique_info = {
        "technique_id": "T1046", "technique_name": "x", "tactic": "y", "description": "z",
    }
    prompt = build_prompt("port_scan", "some alert", technique_info)

    # Guards against silently dropping this instruction in a future edit,
    # since it's the main defense against the LLM inventing details.
    assert "do not invent" in prompt.lower()


@patch("src.llm.triage.call_llm")
def test_triage_alert_returns_correct_technique_for_ssh(mock_call_llm):
    mock_call_llm.return_value = "A fake summary of the alert."

    result = triage_alert("ssh_bruteforce", "45 failed attempts from 10.0.0.1")

    assert isinstance(result, TriageResult)
    assert result.technique_id == "T1110.001"
    assert result.technique_name == "Brute Force: Password Guessing"
    assert result.summary == "A fake summary of the alert."


@patch("src.llm.triage.call_llm")
def test_triage_alert_returns_correct_technique_for_port_scan(mock_call_llm):
    mock_call_llm.return_value = "A fake port scan summary."

    result = triage_alert("port_scan", "8 unique ports probed from 10.0.0.1")

    assert result.technique_id == "T1046"
    assert result.technique_name == "Network Service Discovery"


@patch("src.llm.triage.call_llm")
def test_triage_alert_includes_recommended_response_from_kb(mock_call_llm):
    mock_call_llm.return_value = "summary"

    result = triage_alert("ssh_bruteforce", "some alert")

    assert len(result.recommended_response) > 0
    assert any("fail2ban" in step.lower() for step in result.recommended_response)


def test_triage_alert_raises_on_unknown_alert_type():
    with pytest.raises(ValueError):
        triage_alert("unknown_attack_type", "some alert string")


@patch("src.llm.triage.call_llm")
def test_triage_alert_does_not_call_llm_for_unknown_type(mock_call_llm):
    # If the alert type is invalid, we should fail fast before ever spending a call on the LLM (wasted time/resources for a request we already know is malformed).
    with pytest.raises(ValueError):
        triage_alert("unknown_attack_type", "some alert string")

    mock_call_llm.assert_not_called()