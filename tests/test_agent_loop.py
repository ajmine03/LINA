from unittest.mock import MagicMock, patch
import pytest

from agent.orchestrator import SecurityOrchestrator
from agent.planner import PlanStep, Planner
from agent.scope import ScopeConfig


def test_orchestrator_scope_rejection(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.memory.RUNS_DIR", tmp_path)
    monkeypatch.setattr("tools.report.REPORTS_DIR", tmp_path)

    scope = ScopeConfig(name="internal_only", allowed_ips=["192.168.1.10"])
    orchestrator = SecurityOrchestrator(scope=scope, interactive=False, max_steps=3)

    memory = orchestrator.run("8.8.8.8")
    assert memory.stop_reason is not None
    assert "OUT OF SCOPE" in memory.stop_reason
    assert len(memory.tool_history) == 0


def test_planner_fallback_sequence():
    planner = Planner()
    # When Ollama is offline or unmocked, it must safely return deterministic fallback steps
    step1 = planner.plan_next_step("example.com", 1, [], "None")
    assert step1.tool_name == "dns_lookup"
    assert step1.stop is False

    step2 = planner.plan_next_step("example.com", 2, ["dns_lookup"], "None")
    assert step2.tool_name == "http_probe"

    step3 = planner.plan_next_step("example.com", 3, ["dns_lookup", "http_probe"], "None")
    assert step3.tool_name == "tls_check"

    step4 = planner.plan_next_step("example.com", 4, ["dns_lookup", "http_probe", "tls_check"], "None")
    assert step4.tool_name == "report"
    assert step4.stop is True


def test_planner_json_repair_and_extraction():
    planner = Planner()

    # Markdown wrapped JSON
    text_with_markdown = """Here is your planned step:
    ```json
    {
        "thought": "Let us check DNS first",
        "tool_name": "dns_lookup",
        "parameters": {"target": "127.0.0.1"},
        "stop": false
    }
    ```
    """
    step = planner._parse_json_plan(text_with_markdown)
    assert step is not None
    assert step.tool_name == "dns_lookup"
    assert step.thought == "Let us check DNS first"

    # Malformed text
    assert planner._parse_json_plan("Not JSON at all") is None


def test_orchestrator_bounded_loop(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.memory.RUNS_DIR", tmp_path)
    monkeypatch.setattr("tools.report.REPORTS_DIR", tmp_path)

    scope = ScopeConfig(name="local", allowed_ips=["127.0.0.1"])
    # Run with max_steps=2
    orchestrator = SecurityOrchestrator(scope=scope, interactive=False, max_steps=2)

    # Force planner to always suggest dns_lookup
    orchestrator.planner.plan_next_step = MagicMock(return_value=PlanStep(
        thought="Test repetition",
        tool_name="dns_lookup",
        parameters={"target": "127.0.0.1"},
        stop=False
    ))

    memory = orchestrator.run("127.0.0.1")
    assert memory.step_count == 2
    assert len(memory.tool_history) == 2
