import subprocess
import sys
import pytest


def test_cli_help():
    result = subprocess.run([sys.executable, "main.py", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "scan" in result.stdout
    assert "tools" in result.stdout
    assert "status" in result.stdout


def test_cli_tools():
    result = subprocess.run([sys.executable, "main.py", "tools"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "dns_lookup" in result.stdout
    assert "http_probe" in result.stdout
    assert "tls_check" in result.stdout
    assert "nmap" in result.stdout
    assert "report" in result.stdout


def test_cli_knowledge_search():
    result = subprocess.run([sys.executable, "main.py", "knowledge", "search", "header"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "CTF-WEB-001" in result.stdout
