"""
Security Policy and Guardrail Layer for LINA.
Enforces tool whitelists, argument safety, action risk categorization,
and mandatory human-in-the-loop approval gates.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ActionRisk(str, Enum):
    PASSIVE = "PASSIVE"         # DNS lookup, TLS certificate check, local report generation
    ACTIVE = "ACTIVE"           # HTTP probing, Nmap port scanning / version enumeration
    PROHIBITED = "PROHIBITED"   # Exploits, brute force, DoS, shell injection, persistence


# Strictly allowed tool names
ALLOWED_TOOLS = {
    "dns_lookup",
    "http_probe",
    "tls_check",
    "nmap",
    "report",
}

# Dangerous / Prohibited patterns in any tool arguments or inputs
PROHIBITED_ARG_PATTERNS = [
    r"[;&|`$><]",                  # Shell command chaining / redirection / interpolation
    r"\brm\s+-rf\b",               # Filesystem destruction
    r"\bexploit\b",                # Exploit scripts / payloads
    r"\bdos\b",                    # Denial of service scripts
    r"\bbrute\b",                  # Brute force scripts
    r"\bhydra\b",                  # Credential attack tools
    r"\bsqlmap\b",                 # Automated exploitation
    r"\bmetasploit\b",             # Exploit framework
    r"\bmsfconsole\b",
    r"\bcrack\b",
    r"--script=.*exploit.*",
    r"--script=.*dos.*",
    r"--script=.*fuzzer.*",
]


class PolicyViolation(Exception):
    """Raised when an operation violates security policy."""
    pass


class PolicyEngine:
    def __init__(self, auto_approve_passive: bool = True, require_approval_for_active: bool = True):
        self.auto_approve_passive = auto_approve_passive
        self.require_approval_for_active = require_approval_for_active

    def categorize_action(self, tool_name: str) -> ActionRisk:
        if tool_name not in ALLOWED_TOOLS:
            return ActionRisk.PROHIBITED
        if tool_name in {"dns_lookup", "tls_check", "report"}:
            return ActionRisk.PASSIVE
        if tool_name in {"http_probe", "nmap"}:
            return ActionRisk.ACTIVE
        return ActionRisk.PROHIBITED

    def validate_tool_call(self, tool_name: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates whether a tool call is permitted and its parameters are safe.
        Returns (is_valid, reason).
        """
        if tool_name not in ALLOWED_TOOLS:
            return False, f"Tool '{tool_name}' is not in the authorized tools whitelist: {list(ALLOWED_TOOLS)}"

        # Validate arguments for prohibited patterns
        for key, value in params.items():
            str_val = str(value)
            for pattern in PROHIBITED_ARG_PATTERNS:
                if re.search(pattern, str_val, re.IGNORECASE):
                    return False, f"Prohibited pattern '{pattern}' detected in parameter '{key}'='{str_val}'"

        # Specific checks for nmap
        if tool_name == "nmap":
            valid, reason = self._validate_nmap_params(params)
            if not valid:
                return False, reason

        return True, "Tool call complies with security policy."

    def _validate_nmap_params(self, params: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Ensures nmap is restricted strictly to non-destructive host/version enumeration.
        """
        allowed_keys = {"target", "ports", "timing", "version_detection", "service_detection", "open_only"}
        for k in params:
            if k not in allowed_keys:
                return False, f"Nmap argument '{k}' is not allowed. Only non-destructive discovery arguments permitted."

        ports = params.get("ports")
        if ports is not None:
            # Ports should be comma-separated integers, ranges like 1-1000, or standard strings like 'top100'
            ports_str = str(ports).strip()
            if not re.fullmatch(r"^(top\d{1,4}|\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$", ports_str, re.IGNORECASE):
                return False, f"Invalid or unsafe port specification: '{ports_str}'"

        timing = params.get("timing")
        if timing is not None:
            # Allow T1 through T4 only (T5 is aggressive/flooding)
            if str(timing) not in {"T1", "T2", "T3", "T4", "1", "2", "3", "4"}:
                return False, f"Timing template '{timing}' not permitted. Use T1-T4 for safe rate-limiting."

        return True, "Nmap arguments are safe and compliant."

    def request_approval(self, tool_name: str, target: str, params: Dict[str, Any], interactive: bool = True) -> Tuple[bool, str]:
        """
        Enforces human approval gates before executing active tools.
        """
        risk = self.categorize_action(tool_name)
        if risk == ActionRisk.PROHIBITED:
            return False, f"Action '{tool_name}' is PROHIBITED by security policy."

        if risk == ActionRisk.PASSIVE and self.auto_approve_passive:
            return True, "Passive action auto-approved by policy."

        # Active actions require explicit approval
        if not interactive:
            # Non-interactive mode (e.g. headless) must have pre-approved settings or reject
            return False, f"Interactive approval required for ACTIVE tool '{tool_name}' on target '{target}'."

        # Display approval prompt in terminal
        print("\n" + "=" * 50)
        print(f"🔒 HUMAN APPROVAL REQUIRED FOR ACTIVE SECURITY ACTION")
        print(f"Tool:    {tool_name} (Risk Level: {risk.value})")
        print(f"Target:  {target}")
        print(f"Params:  {params}")
        print("=" * 50)

        try:
            choice = input("Authorize this test on approved target? [y/N]: ").strip().lower()
            if choice in {"y", "yes"}:
                return True, "Authorized by operator."
            return False, "Operator rejected execution."
        except (KeyboardInterrupt, EOFError):
            print("\nAborted by user.")
            return False, "Operator cancelled input."
