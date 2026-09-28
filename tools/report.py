"""
Security Assessment Report Generator.
Produces structured JSON and Markdown audit reports separating observations
from hypotheses, confidence levels, limitations, and remediation guidance.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from config import REPORTS_DIR
from agent.scope import ScopeConfig
from tools.base import BaseTool, ToolResult


class ReportGeneratorTool(BaseTool):
    name: str = "report"
    description: str = "Compiles structured evidence, observations, hypotheses, and remediations into Markdown and JSON reports."
    requires_scope: bool = False
    is_active: bool = False

    def execute(self, target: str, params: Optional[Dict[str, Any]] = None, scope: Optional[ScopeConfig] = None) -> ToolResult:
        params = params or {}
        run_id = params.get("run_id", f"run_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        executive_summary = params.get("executive_summary", "Automated non-destructive security assessment completed.")
        findings = params.get("findings", [])
        evidence_timeline = params.get("evidence_timeline", [])
        scope_info = scope.model_dump() if scope else {"name": "unspecified"}

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        report_data = {
            "run_id": run_id,
            "target": target,
            "generated_at": timestamp,
            "scope": scope_info,
            "executive_summary": executive_summary,
            "findings_count": len(findings),
            "findings": findings,
            "audit_trail": evidence_timeline,
        }

        # Save JSON
        json_path = REPORTS_DIR / f"{run_id}_report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        # Generate Markdown
        md_content = self._render_markdown(report_data)
        md_path = REPORTS_DIR / f"{run_id}_report.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return ToolResult(
            tool_name=self.name,
            target=target,
            success=True,
            data={
                "run_id": run_id,
                "json_report": str(json_path),
                "markdown_report": str(md_path),
                "findings_count": len(findings)
            },
            raw_output=f"Reports generated successfully:\n- {md_path}\n- {json_path}"
        )

    def _render_markdown(self, data: Dict[str, Any]) -> str:
        lines = [
            f"# LINA Security Assessment Report",
            f"",
            f"**Run ID:** `{data['run_id']}`  ",
            f"**Target:** `{data['target']}`  ",
            f"**Date:** `{data['generated_at']}`  ",
            f"**Scope Name:** `{data['scope'].get('name', 'N/A')}`  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary",
            f"",
            data["executive_summary"],
            f"",
            f"---",
            f"",
            f"## 2. Findings & Observations Summary",
            f"",
            f"Total Findings Identified: **{len(data['findings'])}**",
            f"",
        ]

        if not data["findings"]:
            lines.append("No security anomalies or hardening weaknesses detected within the authorized scope.\n")
        else:
            for idx, finding in enumerate(data["findings"], start=1):
                title = finding.get("title", f"Finding #{idx}")
                severity = finding.get("severity", "INFORMATIONAL").upper()
                asset = finding.get("affected_asset", data["target"])
                evidence = finding.get("evidence", "No raw evidence recorded.")
                hypothesis = finding.get("hypothesis", "None")
                confidence = finding.get("confidence", "Medium")
                limitations = finding.get("limitations", "Based solely on passive/non-destructive observation.")
                remediation = finding.get("remediation", "Apply vendor security best practices.")

                lines.extend([
                    f"### 2.{idx} [{severity}] {title}",
                    f"",
                    f"* **Affected Asset:** `{asset}`",
                    f"* **Confidence Level:** {confidence}",
                    f"* **Status:** Verified Observation (Non-destructive)",
                    f"",
                    f"#### 🔍 Observed Evidence",
                    f"```text",
                    evidence.strip(),
                    f"```",
                    f"",
                    f"#### 💡 Analytical Hypothesis / Potential Impact",
                    f"{hypothesis}",
                    f"",
                    f"#### ⚠️ Scope & Limitations",
                    f"{limitations}",
                    f"",
                    f"#### 🛡️ Defensive Remediation Guidance",
                    f"{remediation}",
                    f"",
                    f"---",
                ])

        lines.extend([
            f"## 3. Tool Execution & Audit Trail",
            f"",
            f"| Timestamp | Tool | Target | Status | Duration (s) |",
            f"|---|---|---|---|---|",
        ])

        for event in data["audit_trail"]:
            ts = event.get("timestamp", "")
            t_name = event.get("tool_name", "")
            tgt = event.get("target", "")
            status = "SUCCESS" if event.get("success") else "FAILED"
            dur = event.get("duration_seconds", 0.0)
            lines.append(f"| {ts} | `{t_name}` | `{tgt}` | {status} | {dur} |")

        lines.extend([
            f"",
            f"---",
            f"*Report generated by LINA (Linux Intelligent Native Assistant) — Local-First Security Agent.*",
            f"*Disclaimer: This report reflects observations gathered through approved, non-destructive security testing.*"
        ])

        return "\n".join(lines)
