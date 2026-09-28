"""
Nmap Tool: Performs strictly non-destructive port discovery and service/version enumeration.
Always uses parameterized subprocess lists (never shell=True).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

from config import DEFAULT_TOOL_TIMEOUT, NMAP_AVAILABLE
from agent.scope import ScopeConfig, extract_host_from_target
from tools.base import BaseTool, ToolResult


class NmapTool(BaseTool):
    name: str = "nmap"
    description: str = "Non-destructive port discovery and service version enumeration using Nmap."
    requires_scope: bool = True
    is_active: bool = True
    timeout: int = 120  # Port scans can take slightly longer

    def execute(self, target: str, params: Optional[Dict[str, Any]] = None, scope: Optional[ScopeConfig] = None) -> ToolResult:
        start_time = time.time()
        self.enforce_scope(target, scope)

        if not shutil.which("nmap"):
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error="Nmap binary not found on system PATH. Install nmap or use passive tools.",
                raw_output="Nmap not available.",
                duration_seconds=round(time.time() - start_time, 3)
            )

        host = extract_host_from_target(target)
        params = params or {}

        ports = str(params.get("ports", "top100")).strip()
        timing = str(params.get("timing", "T3")).strip()
        service_version = bool(params.get("version_detection", True))

        # Build parameterized command list strictly without shell=True
        cmd = ["nmap", "-oX", "-"]

        # Timing template
        if timing in ("T1", "T2", "T3", "T4"):
            cmd.append(f"-{timing}")
        else:
            cmd.append("-T3")

        # Port selection
        if ports == "top100":
            cmd.extend(["--top-ports", "100"])
        elif re.fullmatch(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$", ports):
            cmd.extend(["-p", ports])
        else:
            cmd.extend(["--top-ports", "100"])

        if service_version:
            cmd.append("-sV")

        cmd.append("--open")  # Non-destructive, ignore closed ports to reduce traffic
        cmd.append(host)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )

            if result.returncode != 0 and not result.stdout:
                return ToolResult(
                    tool_name=self.name,
                    target=target,
                    success=False,
                    error=result.stderr.strip() or "Nmap failed with non-zero exit code.",
                    raw_output=result.stderr.strip(),
                    duration_seconds=round(time.time() - start_time, 3)
                )

            # Parse XML output
            parsed_ports = self._parse_nmap_xml(result.stdout)

            # Generate clean summary
            summary_lines = [f"Nmap scan for {host}:"]
            for p in parsed_ports:
                summary_lines.append(f"  Port {p['port']}/{p['protocol']}: {p['state']} - {p['service']} {p.get('version', '')}".strip())

            raw_summary = "\n".join(summary_lines)

            return ToolResult(
                tool_name=self.name,
                target=target,
                success=True,
                data={"host": host, "open_ports": parsed_ports, "port_count": len(parsed_ports)},
                raw_output=self.truncate_output(raw_summary),
                duration_seconds=round(time.time() - start_time, 3)
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=f"Nmap scan timed out after {self.timeout} seconds.",
                raw_output="Timeout expired.",
                duration_seconds=round(time.time() - start_time, 3)
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                target=target,
                success=False,
                error=str(e),
                raw_output=f"Error executing nmap: {e}",
                duration_seconds=round(time.time() - start_time, 3)
            )

    def _parse_nmap_xml(self, xml_content: str) -> List[Dict[str, Any]]:
        """Safely parses Nmap XML output for open ports and services."""
        ports_list = []
        if not xml_content.strip():
            return ports_list

        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                ports_elem = host.find("ports")
                if ports_elem is None:
                    continue
                for port_elem in ports_elem.findall("port"):
                    port_id = port_elem.get("portid")
                    protocol = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"

                    if state != "open":
                        continue

                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    extra = service_elem.get("extrainfo", "") if service_elem is not None else ""

                    version_str = f"{product} {version} {extra}".strip()

                    ports_list.append({
                        "port": int(port_id) if port_id and port_id.isdigit() else port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service_name,
                        "version": version_str
                    })
        except ET.ParseError:
            # Fallback regex parsing if XML root was incomplete
            for line in xml_content.splitlines():
                m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$", line.strip())
                if m:
                    ports_list.append({
                        "port": int(m.group(1)),
                        "protocol": m.group(2),
                        "state": m.group(3),
                        "service": m.group(4).strip(),
                        "version": ""
                    })

        return ports_list
