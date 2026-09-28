"""
DNS Lookup Tool: Performs non-destructive DNS queries (A, AAAA, CNAME, PTR).
"""

from __future__ import annotations

import socket
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agent.scope import ScopeConfig, extract_host_from_target
from tools.base import BaseTool, ToolResult


class DNSLookupInput(BaseModel):
    target: str
    record_types: List[str] = Field(default_factory=lambda: ["A", "AAAA", "PTR", "CNAME"])


class DNSLookupTool(BaseTool):
    name: str = "dns_lookup"
    description: str = "Performs non-destructive DNS resolution (A, AAAA, CNAME, PTR) for authorized targets."
    requires_scope: bool = True
    is_active: bool = False

    def execute(self, target: str, params: Optional[Dict[str, Any]] = None, scope: Optional[ScopeConfig] = None) -> ToolResult:
        start_time = time.time()
        self.enforce_scope(target, scope)

        host = extract_host_from_target(target)
        records: Dict[str, Any] = {"host": host, "a_records": [], "aaaa_records": [], "cname": None, "ptr": None}
        errors: List[str] = []

        # Resolve IPv4 (A) & CNAME
        try:
            cname, aliases, ip_list = socket.gethostbyname_ex(host)
            records["cname"] = cname if cname != host else None
            records["aliases"] = aliases
            records["a_records"] = ip_list
        except socket.gaierror as e:
            errors.append(f"A record resolution error: {e}")

        # Resolve IPv6 (AAAA)
        try:
            addr_info = socket.getaddrinfo(host, None, socket.AF_INET6)
            aaaa_list = list(set([item[4][0] for item in addr_info]))
            records["aaaa_records"] = aaaa_list
        except (socket.gaierror, socket.error):
            # No AAAA is common, not necessarily a hard failure
            pass

        # Reverse lookup (PTR)
        if records["a_records"]:
            try:
                primary_ip = records["a_records"][0]
                ptr, _, _ = socket.gethostbyaddr(primary_ip)
                records["ptr"] = ptr
            except (socket.herror, socket.gaierror):
                pass
        else:
            # If target was directly an IP
            try:
                ptr, _, _ = socket.gethostbyaddr(host)
                records["ptr"] = ptr
            except (socket.herror, socket.gaierror, ValueError):
                pass

        elapsed = time.time() - start_time
        success = bool(records["a_records"] or records["aaaa_records"] or records["ptr"])

        raw_output = f"DNS records for {host}:\n"
        if records["a_records"]:
            raw_output += f"  A: {', '.join(records['a_records'])}\n"
        if records["aaaa_records"]:
            raw_output += f"  AAAA: {', '.join(records['aaaa_records'])}\n"
        if records["cname"]:
            raw_output += f"  CNAME: {records['cname']}\n"
        if records["ptr"]:
            raw_output += f"  PTR: {records['ptr']}\n"
        if errors:
            raw_output += f"  Errors: {'; '.join(errors)}\n"

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=success,
            data=records,
            raw_output=self.truncate_output(raw_output.strip()),
            error="; ".join(errors) if (not success and errors) else None,
            duration_seconds=round(elapsed, 3),
        )
