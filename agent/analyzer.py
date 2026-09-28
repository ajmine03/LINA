"""
Evidence-based Security Analyzer for LINA.
Separates factual observations from hypotheses.
Sanitizes untrusted output to protect against prompt injection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from tools.base import ToolResult


# Patterns that could be used for prompt injection or system prompt spoofing in banners/output
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+instructions\b", "[FILTERED_INJECTION_ATTEMPT]"),
    (r"(?i)\byou\s+are\s+now\s+an?\s+unrestricted\b", "[FILTERED_INJECTION_ATTEMPT]"),
    (r"(?i)\bsystem\s*:\s*", "[FILTERED_SYSTEM_TAG]"),
    (r"<\|im_start\|>", "[FILTERED_TOKEN]"),
    (r"<\|im_end\|>", "[FILTERED_TOKEN]"),
    (r"<\|endoftext\|>", "[FILTERED_TOKEN]"),
    (r"(?i)\bexecute\s+command\s*:\s*", "[FILTERED_COMMAND_INJECTION]"),
]


def sanitize_untrusted_text(text: str, max_chars: int = 4000) -> str:
    """
    Sanitizes untrusted text (banners, HTTP headers, DNS outputs, HTML responses)
    to defend against prompt injection when fed into an LLM or logs.
    """
    if not text:
        return ""

    sanitized = text
    for pattern, replacement in PROMPT_INJECTION_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized)

    # Truncate if excessively long
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + "\n... [TRUNCATED FOR ANALYSIS]"

    return sanitized


class EvidenceAnalyzer:
    """
    Parses structured tool results into evidence-based security findings.
    Strictly prevents claiming a vulnerability is confirmed solely based on a version banner.
    """

    def analyze(self, result: ToolResult) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if not result.success:
            return findings

        if result.tool_name == "http_probe":
            findings.extend(self._analyze_http_probe(result))
        elif result.tool_name == "tls_check":
            findings.extend(self._analyze_tls_check(result))
        elif result.tool_name == "nmap":
            findings.extend(self._analyze_nmap(result))
        elif result.tool_name == "dns_lookup":
            findings.extend(self._analyze_dns(result))

        return findings

    def _analyze_http_probe(self, result: ToolResult) -> List[Dict[str, Any]]:
        findings = []
        data = result.data
        target_url = data.get("url", result.target)

        # Check missing security headers
        for item in data.get("findings", []):
            if item.get("type") == "missing_security_header":
                header = item.get("header")
                findings.append({
                    "title": f"Missing Defensive Header: {header}",
                    "severity": "LOW",
                    "affected_asset": target_url,
                    "evidence": f"HTTP response headers omitted '{header}'.",
                    "hypothesis": f"Clients connecting to this asset lack protections provided by {header}.",
                    "confidence": "VERIFIED_OBSERVATION",
                    "limitations": "Observed via direct HTTP response without executing active payloads.",
                    "remediation": item.get("recommendation", f"Configure {header} in web server responses.")
                })

        # Check server banner exposure
        banner = data.get("server_banner")
        if banner:
            clean_banner = sanitize_untrusted_text(banner)
            findings.append({
                "title": f"Server Banner Exposure: {clean_banner[:40]}",
                "severity": "INFORMATIONAL",
                "affected_asset": target_url,
                "evidence": f"Server header returned: '{clean_banner}'.",
                "hypothesis": "Banner exposes server software family, assisting external fingerprinting.",
                "confidence": "VERIFIED_OBSERVATION (Software version unconfirmed without deeper verification)",
                "limitations": "Banners may be obfuscated or misleading; does NOT confirm exploitable vulnerability.",
                "remediation": "Disable or minimize Server response banner (e.g. ServerTokens Prod in Apache, server_tokens off in Nginx)."
            })

        return findings

    def _analyze_tls_check(self, result: ToolResult) -> List[Dict[str, Any]]:
        findings = []
        data = result.data
        host_port = f"{data.get('host', result.target)}:{data.get('port', 443)}"

        for item in data.get("findings", []):
            severity = item.get("severity", "MEDIUM")
            f_type = item.get("type", "tls_issue")
            findings.append({
                "title": f"TLS Configuration: {f_type.replace('_', ' ').title()}",
                "severity": severity,
                "affected_asset": host_port,
                "evidence": item.get("description", "TLS check anomaly."),
                "hypothesis": "Sub-optimal or expired TLS config increases risk of encrypted traffic degradation or MITM warnings.",
                "confidence": "VERIFIED_OBSERVATION",
                "limitations": "Tested using standard TLS handshake parameters.",
                "remediation": item.get("recommendation", "Update TLS certificate or configuration.")
            })

        return findings

    def _analyze_nmap(self, result: ToolResult) -> List[Dict[str, Any]]:
        findings = []
        data = result.data
        host = data.get("host", result.target)
        open_ports = data.get("open_ports", [])

        for p in open_ports:
            port_num = p.get("port")
            service = p.get("service", "unknown")
            version = p.get("version", "").strip()

            findings.append({
                "title": f"Exposed Service: Port {port_num}/{p.get('protocol', 'tcp')} ({service})",
                "severity": "INFORMATIONAL",
                "affected_asset": f"{host}:{port_num}",
                "evidence": f"Port {port_num} open. Service banner reported: '{version or service}'.",
                "hypothesis": f"Service is network-accessible. If not required publicly, exposes unnecessary attack surface.",
                "confidence": "VERIFIED_OBSERVATION (Service presence confirmed; specific vulnerabilities unverified)",
                "limitations": "Discovered via non-destructive port probe. Banner was not validated for backports or false positives.",
                "remediation": f"Ensure port {port_num} is restricted to authorized IP ranges via firewall if not intended for public access."
            })

        return findings

    def _analyze_dns(self, result: ToolResult) -> List[Dict[str, Any]]:
        findings = []
        data = result.data
        host = data.get("host", result.target)
        a_records = data.get("a_records", [])

        if a_records:
            findings.append({
                "title": f"DNS Resolution: {host}",
                "severity": "INFORMATIONAL",
                "affected_asset": host,
                "evidence": f"Resolved A records: {', '.join(a_records)}",
                "hypothesis": "Standard DNS mapping for asset discovery.",
                "confidence": "VERIFIED_OBSERVATION",
                "limitations": "Based on standard DNS resolver queries.",
                "remediation": "Ensure DNS records are regularly pruned of decommissioned hosts to prevent subdomain takeovers."
            })

        return findings
