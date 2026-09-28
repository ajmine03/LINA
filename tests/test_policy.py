import pytest
from agent.policy import ActionRisk, PolicyEngine


def test_tool_categorization():
    engine = PolicyEngine()
    assert engine.categorize_action("dns_lookup") == ActionRisk.PASSIVE
    assert engine.categorize_action("tls_check") == ActionRisk.PASSIVE
    assert engine.categorize_action("report") == ActionRisk.PASSIVE
    assert engine.categorize_action("http_probe") == ActionRisk.ACTIVE
    assert engine.categorize_action("nmap") == ActionRisk.ACTIVE
    assert engine.categorize_action("metasploit") == ActionRisk.PROHIBITED
    assert engine.categorize_action("hydra") == ActionRisk.PROHIBITED


def test_reject_unauthorized_tool():
    engine = PolicyEngine()
    valid, reason = engine.validate_tool_call("sqlmap", {"target": "127.0.0.1"})
    assert valid is False
    assert "whitelist" in reason


def test_prohibited_argument_injection():
    engine = PolicyEngine()
    # Shell chaining attempt
    valid, reason = engine.validate_tool_call("dns_lookup", {"target": "127.0.0.1; cat /etc/passwd"})
    assert valid is False
    assert "Prohibited pattern" in reason

    # Exploit keyword
    valid, reason = engine.validate_tool_call("http_probe", {"target": "127.0.0.1", "path": "/exploit/payload"})
    assert valid is False
    assert "Prohibited pattern" in reason


def test_nmap_validation():
    engine = PolicyEngine()
    # Safe params
    valid, reason = engine.validate_tool_call("nmap", {"target": "127.0.0.1", "ports": "80,443", "timing": "T3"})
    assert valid is True

    # Dangerous script flag
    valid, reason = engine.validate_tool_call("nmap", {"target": "127.0.0.1", "ports": "80", "timing": "T5"})
    assert valid is False
    assert "Timing template" in reason

    # Disallowed argument
    valid, reason = engine.validate_tool_call("nmap", {"target": "127.0.0.1", "raw_args": "--script=vuln"})
    assert valid is False
    assert "not allowed" in reason


def test_approval_gates():
    engine = PolicyEngine(auto_approve_passive=True)
    # Passive is auto approved
    approved, _ = engine.request_approval("dns_lookup", "127.0.0.1", {}, interactive=False)
    assert approved is True

    # Active without interactive approval must fail
    approved, reason = engine.request_approval("nmap", "127.0.0.1", {"ports": "80"}, interactive=False)
    assert approved is False
    assert "Interactive approval required" in reason

    # Prohibited action fails regardless
    approved, reason = engine.request_approval("metasploit", "127.0.0.1", {}, interactive=True)
    assert approved is False
    assert "PROHIBITED" in reason
