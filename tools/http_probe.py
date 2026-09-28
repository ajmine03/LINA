"""
HTTP Probe Tool: Gathers HTTP metadata, server banners, security headers,
and checks cookies while enforcing redirect scope boundaries.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
import httpx
from pydantic import BaseModel, Field

from agent.scope import ScopeConfig, extract_host_from_target
from tools.base import BaseTool, ToolResult


class HTTPProbeInput(BaseModel):
    target: str
    port: Optional[int] = None
    path: str = "/"
    method: str = "HEAD"


class HTTPProbeTool(BaseTool):
    name: str = "http_probe"
    description: str = "Performs non-destructive HTTP metadata and security header inspection."
    requires_scope: bool = True
    is_active: bool = True

    def execute(self, target: str, params: Optional[Dict[str, Any]] = None, scope: Optional[ScopeConfig] = None) -> ToolResult:
        start_time = time.time()
        self.enforce_scope(target, scope)

        params = params or {}
        path = params.get("path", "/")
        if not path.startswith("/"):
            path = "/" + path

        port = params.get("port")
        host = extract_host_from_target(target)

        # Formulate URL
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            scheme = parsed.scheme
            netloc = host
            if port:
                netloc = f"{host}:{port}"
            elif parsed.port:
                netloc = f"{host}:{parsed.port}"
            target_path = parsed.path if parsed.path else "/"
            effective_path = params.get("path") if params.get("path") else target_path
            if not effective_path.startswith("/"):
                effective_path = "/" + effective_path
            url = f"{scheme}://{netloc}{effective_path}"
        else:
            # Default to http or https based on port
            scheme = "https" if port in (443, 8443) else "http"
            netloc = f"{host}:{port}" if port else host
            url = f"{scheme}://{netloc}{path}"

        headers_analyzed: Dict[str, Any] = {}
        findings: List[Dict[str, str]] = []
        status_code = None
        server_banner = None

        try:
            with httpx.Client(trust_env=False, follow_redirects=False, verify=False, timeout=self.timeout) as client:
                # Try HEAD first, fallback to GET if 405 Method Not Allowed
                method = params.get("method", "HEAD").upper()
                try:
                    response = client.request(method, url)
                except httpx.HTTPError:
                    if method == "HEAD":
                        response = client.get(url)
                    else:
                        raise

                status_code = response.status_code
                server_banner = response.headers.get("server")

                # Analyze Security Headers
                sec_headers = {
                    "Strict-Transport-Security": response.headers.get("strict-transport-security"),
                    "Content-Security-Policy": response.headers.get("content-security-policy"),
                    "X-Frame-Options": response.headers.get("x-frame-options"),
                    "X-Content-Type-Options": response.headers.get("x-content-type-options"),
                    "Referrer-Policy": response.headers.get("referrer-policy"),
                    "Permissions-Policy": response.headers.get("permissions-policy"),
                }
                headers_analyzed = sec_headers

                # Check for missing standard defensive headers
                for h_name, h_val in sec_headers.items():
                    if not h_val:
                        findings.append({
                            "type": "missing_security_header",
                            "header": h_name,
                            "severity": "LOW",
                            "recommendation": f"Configure {h_name} header to harden HTTP responses."
                        })

                # Check redirects and scope boundary
                redirect_location = response.headers.get("location")
                redirect_info = None
                if status_code in (301, 302, 303, 307, 308) and redirect_location:
                    full_redirect_url = urljoin(url, redirect_location)
                    if scope:
                        allowed, reason = scope.validate_redirect(url, full_redirect_url)
                        redirect_info = {
                            "redirect_url": full_redirect_url,
                            "in_scope": allowed,
                            "policy_decision": reason
                        }
                    else:
                        redirect_info = {"redirect_url": full_redirect_url, "in_scope": False, "policy_decision": "No scope defined."}

                data = {
                    "url": url,
                    "status_code": status_code,
                    "server_banner": server_banner,
                    "security_headers": sec_headers,
                    "redirect": redirect_info,
                    "missing_headers_count": len(findings),
                    "findings": findings
                }

                raw_output = f"HTTP Probe: {url} -> Status {status_code}\n"
                if server_banner:
                    raw_output += f"Server Banner: {server_banner}\n"
                raw_output += f"Security Headers Detected:\n"
                for h, v in sec_headers.items():
                    raw_output += f"  {h}: {v if v else '[MISSING]'}\n"
                if redirect_info:
                    raw_output += f"Redirect to: {redirect_info['redirect_url']} (Allowed: {redirect_info['in_scope']})\n"

                return ToolResult(
                    tool_name=self.name,
                    target=target,
                    success=True,
                    data=data,
                    raw_output=self.truncate_output(raw_output.strip()),
                    duration_seconds=round(time.time() - start_time, 3)
                )

        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                data={},
                raw_output=f"HTTP probe failed for {url}: {str(e)}",
                error=str(e),
                duration_seconds=round(time.time() - start_time, 3)
            )
