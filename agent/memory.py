"""
Execution memory and audit logging for LINA Security Agent.
Maintains session state, tool execution history, findings, and immutable audit logs.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from config import RUNS_DIR
from agent.scope import ScopeConfig
from tools.base import ToolResult


class AuditEntry(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    run_id: str
    target: str
    tool_name: str
    parameters: Dict[str, Any]
    approved: bool
    approval_reason: str
    success: bool
    duration_seconds: float
    error: Optional[str] = None


class RunMemory:
    def __init__(self, target: str, scope: Optional[ScopeConfig] = None, run_id: Optional[str] = None):
        self.target = target
        self.scope = scope
        self.run_id = run_id or f"run_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.run_dir = RUNS_DIR / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.audit_file = self.run_dir / "audit.jsonl"

        self.step_count = 0
        self.findings: List[Dict[str, Any]] = []
        self.tool_history: List[ToolResult] = []
        self.audit_entries: List[AuditEntry] = []
        self.stop_reason: Optional[str] = None

    def log_action(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        approved: bool,
        approval_reason: str,
        tool_result: Optional[ToolResult] = None
    ) -> AuditEntry:
        """Records an action to the immutable audit trail."""
        entry = AuditEntry(
            run_id=self.run_id,
            target=self.target,
            tool_name=tool_name,
            parameters=parameters,
            approved=approved,
            approval_reason=approval_reason,
            success=tool_result.success if tool_result else False,
            duration_seconds=tool_result.duration_seconds if tool_result else 0.0,
            error=tool_result.error if tool_result else None
        )
        self.audit_entries.append(entry)

        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")

        if tool_result:
            self.tool_history.append(tool_result)

        return entry

    def add_findings(self, new_findings: List[Dict[str, Any]]) -> None:
        """Aggregates new findings into memory while avoiding exact duplicates."""
        for f in new_findings:
            title = f.get("title", "")
            asset = f.get("affected_asset", "")
            # Check duplicate by title & asset
            if not any(existing.get("title") == title and existing.get("affected_asset") == asset for existing in self.findings):
                self.findings.append(f)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "step_count": self.step_count,
            "total_tools_executed": len(self.tool_history),
            "findings_count": len(self.findings),
            "stop_reason": self.stop_reason,
            "audit_log_path": str(self.audit_file)
        }
