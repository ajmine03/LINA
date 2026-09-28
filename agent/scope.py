"""
Scope validation engine for LINA Security Testing Agent.
Enforces strict boundaries on targets (IPs, CIDRs, hostnames/domains, URLs).
Prevents out-of-scope redirection and unauthorized target expansion.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
from pydantic import BaseModel, Field


class ScopeConfig(BaseModel):
    name: str = "default_scope"
    description: str = "Authorized security testing scope"
    allowed_ips: List[str] = Field(default_factory=list)
    allowed_cidrs: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    allow_subdomains: bool = False
    disallowed_targets: List[str] = Field(default_factory=list)
    allowed_ports: Optional[List[int]] = None
    rate_limit_per_minute: int = 60

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeConfig:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Scope file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    @classmethod
    def from_single_target(cls, target: str) -> ScopeConfig:
        """Create a strict scope for a single authorized target."""
        clean = extract_host_from_target(target)
        try:
            # Check if it's an IP
            ipaddress.ip_address(clean)
            return cls(name=f"scope_for_{clean}", allowed_ips=[clean])
        except ValueError:
            pass

        try:
            # Check if it's a CIDR
            ipaddress.ip_network(clean, strict=False)
            return cls(name=f"scope_for_{clean}", allowed_cidrs=[clean])
        except ValueError:
            pass

        # Treat as domain
        return cls(name=f"scope_for_{clean}", allowed_domains=[clean.lower()])

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Validates whether target (IP, domain, or URL) is strictly inside scope.
        Returns (is_allowed, reason).
        """
        host = extract_host_from_target(target)
        if not host:
            return False, "Empty or invalid target host."

        # Check explicit disallow list first
        if host in self.disallowed_targets or target in self.disallowed_targets:
            return False, f"Target '{host}' is explicitly listed in disallowed_targets."

        # Check if host is an IP
        try:
            target_ip = ipaddress.ip_address(host)

            # Check explicit IPs
            for allowed_ip in self.allowed_ips:
                try:
                    if target_ip == ipaddress.ip_address(allowed_ip):
                        return True, f"Matched allowed IP: {allowed_ip}"
                except ValueError:
                    continue

            # Check CIDRs
            for allowed_cidr in self.allowed_cidrs:
                try:
                    network = ipaddress.ip_network(allowed_cidr, strict=False)
                    if target_ip in network:
                        return True, f"Matched allowed CIDR network: {allowed_cidr}"
                except ValueError:
                    continue

            return False, f"IP address {host} is not in allowed IPs or CIDRs."

        except ValueError:
            # host is not an IP; validate as domain
            pass

        host_lower = host.lower()
        for allowed_domain in self.allowed_domains:
            allowed_lower = allowed_domain.lower()
            if host_lower == allowed_lower:
                return True, f"Matched exact allowed domain: {allowed_domain}"
            if self.allow_subdomains and host_lower.endswith("." + allowed_lower):
                return True, f"Matched allowed parent domain: {allowed_domain}"

        return False, f"Domain '{host}' is not in allowed domains: {self.allowed_domains}"

    def validate_redirect(self, original_target: str, redirect_target: str) -> Tuple[bool, str]:
        """
        Ensures an HTTP redirect destination does not cross boundary to an out-of-scope host.
        """
        allowed, reason = self.is_in_scope(redirect_target)
        if not allowed:
            return False, f"Redirect to '{redirect_target}' blocked: outside authorized scope. ({reason})"
        return True, f"Redirect to '{redirect_target}' authorized."


def extract_host_from_target(target: str) -> str:
    """Extracts cleanly the hostname/IP from a string, URL, or host:port."""
    target = target.strip()
    if not target:
        return ""

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        host = parsed.hostname or ""
        return host

    # Remove possible paths or query params if user passed 'domain.com/path'
    if "/" in target and not target.count("/") > 1:  # Not a CIDR like 192.168.1.0/24
        parts = target.split("/", 1)
        # Check if first part looks like a CIDR prefix
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            target = parts[0]

    # Remove port if present, e.g., '127.0.0.1:8080' or 'example.com:443'
    if ":" in target and not target.startswith("[") and target.count(":") == 1:
        target = target.split(":")[0]

    return target.strip()
