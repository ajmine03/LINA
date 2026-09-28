import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from agent.scope import ScopeConfig
from tools.dns_lookup import DNSLookupTool
from tools.http_probe import HTTPProbeTool
from tools.tls_check import TLSCheckTool
from tools.nmap import NmapTool
from tools.report import ReportGeneratorTool


def test_dns_lookup_scope_enforcement():
    tool = DNSLookupTool()
    scope = ScopeConfig(name="test", allowed_domains=["localhost"])

    # Out of scope target should raise PermissionError
    with pytest.raises(PermissionError):
        tool.execute("unauthorized.com", scope=scope)

    # In scope target
    result = tool.execute("localhost", scope=scope)
    assert result.success is True
    assert "127.0.0.1" in result.data.get("a_records", []) or "::1" in result.data.get("aaaa_records", [])


def test_http_probe_with_local_server(local_http_server):
    tool = HTTPProbeTool()
    scope = ScopeConfig(name="test_local", allowed_ips=["127.0.0.1"])

    result = tool.execute(f"http://{local_http_server}/", scope=scope)
    assert result.success is True
    assert result.data["status_code"] == 200
    assert "ToyServer/1.0" in result.data["server_banner"]

    # Should detect missing HSTS & CSP headers
    missing_headers = [f["header"] for f in result.data["findings"] if f["type"] == "missing_security_header"]
    assert "Strict-Transport-Security" in missing_headers
    assert "Content-Security-Policy" in missing_headers


def test_http_probe_redirect_scope_boundary(local_http_server):
    tool = HTTPProbeTool()
    scope = ScopeConfig(name="test_local", allowed_ips=["127.0.0.1"])

    # Internal redirect stays in scope
    res_internal = tool.execute(f"http://{local_http_server}/redirect-internal", scope=scope)
    assert res_internal.data["redirect"]["in_scope"] is True

    # External redirect gets flagged as out-of-scope
    res_external = tool.execute(f"http://{local_http_server}/redirect-external", scope=scope)
    assert res_external.data["redirect"]["in_scope"] is False
    assert "outside authorized scope" in res_external.data["redirect"]["policy_decision"]


def test_tls_check_scope_enforcement():
    tool = TLSCheckTool()
    scope = ScopeConfig(name="test", allowed_ips=["127.0.0.1"])

    with pytest.raises(PermissionError):
        tool.execute("8.8.8.8", scope=scope)


@patch("shutil.which", return_value="/usr/bin/nmap")
@patch("subprocess.run")
def test_nmap_tool_safe_execution(mock_subprocess, mock_which):
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache httpd" version="2.4.41"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    mock_subprocess.return_value = MagicMock(returncode=0, stdout=sample_xml, stderr="")

    tool = NmapTool()
    scope = ScopeConfig(name="test", allowed_ips=["127.0.0.1"])
    result = tool.execute("127.0.0.1", params={"ports": "80", "timing": "T3"}, scope=scope)

    assert result.success is True
    assert len(result.data["open_ports"]) == 1
    assert result.data["open_ports"][0]["port"] == 80
    assert result.data["open_ports"][0]["service"] == "http"

    # Verify subprocess called with a list, NOT shell=True
    cmd_called = mock_subprocess.call_args[0][0]
    assert isinstance(cmd_called, list)
    assert "nmap" == cmd_called[0]
    assert "-p" in cmd_called
    assert "80" in cmd_called
    kwargs = mock_subprocess.call_args[1]
    assert kwargs.get("shell") is not True


def test_report_generator_tool():
    tool = ReportGeneratorTool()
    scope = ScopeConfig(name="test_scope", allowed_ips=["127.0.0.1"])

    findings = [
        {
            "title": "Missing HSTS Header",
            "severity": "LOW",
            "affected_asset": "127.0.0.1:80",
            "evidence": "Strict-Transport-Security: [MISSING]",
            "hypothesis": "Man-in-the-middle attacks could downgrade HTTPS to HTTP.",
            "confidence": "High",
            "limitations": "Tested over HTTP.",
            "remediation": "Enable Strict-Transport-Security header with max-age=31536000."
        }
    ]

    result = tool.execute("127.0.0.1", params={
        "run_id": "test_run_001",
        "findings": findings,
        "evidence_timeline": [{"timestamp": "2026-09-28T00:00:00Z", "tool_name": "http_probe", "target": "127.0.0.1", "success": True, "duration_seconds": 0.05}]
    }, scope=scope)

    assert result.success is True
    json_path = Path(result.data["json_report"])
    md_path = Path(result.data["markdown_report"])

    assert json_path.exists()
    assert md_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["run_id"] == "test_run_001"
        assert len(data["findings"]) == 1

    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Missing HSTS Header" in content
        assert "Defensive Remediation Guidance" in content
