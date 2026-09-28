"""
TLS / SSL Certificate and Configuration Checker.
Gathers certificate validity, issuer, SANs, expiration, protocol version, and ciphers.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from agent.scope import ScopeConfig, extract_host_from_target
from tools.base import BaseTool, ToolResult


class TLSCheckTool(BaseTool):
    name: str = "tls_check"
    description: str = "Inspects TLS/SSL certificate details, validity, expiration, and cipher suites."
    requires_scope: bool = True
    is_active: bool = False

    def execute(self, target: str, params: Optional[Dict[str, Any]] = None, scope: Optional[ScopeConfig] = None) -> ToolResult:
        start_time = time.time()
        self.enforce_scope(target, scope)

        params = params or {}
        port = int(params.get("port", 443))
        host = extract_host_from_target(target)

        findings: List[Dict[str, str]] = []
        cert_data: Dict[str, Any] = {}

        context = ssl.create_default_context()
        # For testing / audit flexibility we allow inspecting certs even if self-signed, but report it!
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_version = ssock.version()
                    cipher_suite = ssock.cipher()
                    # Get binary DER cert for comprehensive parsing
                    der_cert = ssock.getpeercert(binary_form=True)

            # Re-connect or parse cert details with validation context
            val_context = ssl.create_default_context()
            cert_verified = True
            verify_error = None
            try:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with val_context.wrap_socket(sock, server_hostname=host) as ssock:
                        parsed_cert = ssock.getpeercert()
            except ssl.SSLCertVerificationError as e:
                cert_verified = False
                verify_error = str(e)
                parsed_cert = {}

            # Parse validity dates if parsed_cert available
            days_left = None
            expiry_str = parsed_cert.get("notAfter") if parsed_cert else None
            if expiry_str:
                try:
                    expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_left = (expiry_date - now).days

                    if days_left < 0:
                        findings.append({
                            "type": "expired_certificate",
                            "severity": "HIGH",
                            "description": f"Certificate expired {abs(days_left)} days ago on {expiry_str}.",
                            "recommendation": "Renew the TLS certificate immediately."
                        })
                    elif days_left < 30:
                        findings.append({
                            "type": "expiring_certificate",
                            "severity": "MEDIUM",
                            "description": f"Certificate expires in {days_left} days on {expiry_str}.",
                            "recommendation": "Plan certificate renewal prior to expiration."
                        })
                except Exception:
                    pass

            if not cert_verified:
                findings.append({
                    "type": "untrusted_certificate",
                    "severity": "MEDIUM",
                    "description": f"Certificate could not be verified by default trust store: {verify_error}",
                    "recommendation": "Ensure the certificate is issued by a recognized Certificate Authority (CA) and full chain is served."
                })

            if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append({
                    "type": "deprecated_tls_version",
                    "severity": "HIGH",
                    "description": f"Server supports outdated protocol version {tls_version}.",
                    "recommendation": "Upgrade to TLSv1.2 or TLSv1.3 and disable legacy SSL/TLS versions."
                })

            subject = parsed_cert.get("subject", [])
            issuer = parsed_cert.get("issuer", [])
            sans = [v for k, v in parsed_cert.get("subjectAltName", []) if k == "DNS"]

            cert_data = {
                "host": host,
                "port": port,
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "verified_chain": cert_verified,
                "verification_error": verify_error,
                "subject": subject,
                "issuer": issuer,
                "subject_alt_names": sans,
                "expires_on": expiry_str,
                "days_until_expiration": days_left,
                "findings": findings
            }

            raw_output = f"TLS Certificate Check: {host}:{port}\n"
            raw_output += f"  Protocol: {tls_version}\n"
            raw_output += f"  Cipher: {cipher_suite[0] if cipher_suite else 'Unknown'}\n"
            raw_output += f"  Verified by Trust Store: {'Yes' if cert_verified else 'No'}\n"
            if expiry_str:
                raw_output += f"  Expires: {expiry_str} ({days_left} days left)\n"
            if sans:
                raw_output += f"  SANs: {', '.join(sans[:5])}{'...' if len(sans) > 5 else ''}\n"

            return ToolResult(
                tool_name=self.name,
                target=target,
                success=True,
                data=cert_data,
                raw_output=self.truncate_output(raw_output.strip()),
                duration_seconds=round(time.time() - start_time, 3)
            )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                data={},
                raw_output=f"TLS check failed for {host}:{port}: {str(e)}",
                error=str(e),
                duration_seconds=round(time.time() - start_time, 3)
            )
