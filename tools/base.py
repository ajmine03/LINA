"""
BaseTool interface and structured result model for LINA security tools.
"""

from __future__ import annotations

import abc
import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from config import DEFAULT_TOOL_TIMEOUT, MAX_OUTPUT_BYTES
from agent.scope import ScopeConfig


class ToolResult(BaseModel):
    tool_name: str
    target: str
    success: bool
    data: Dict[str, Any] = Field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None
    duration_seconds: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class BaseTool(abc.ABC):
    name: str = "base_tool"
    description: str = "Base interface for all security tools"
    requires_scope: bool = True
    is_active: bool = False
    timeout: int = DEFAULT_TOOL_TIMEOUT

    def enforce_scope(self, target: str, scope: Optional[ScopeConfig]) -> None:
        """Raises PermissionError if target is outside authorized scope."""
        if not self.requires_scope:
            return
        if scope is None:
            raise PermissionError(f"Target '{target}' cannot be tested: No authorized scope provided.")
        in_scope, reason = scope.is_in_scope(target)
        if not in_scope:
            raise PermissionError(f"Target '{target}' is out of authorized scope: {reason}")

    def truncate_output(self, output: str) -> str:
        """Enforces MAX_OUTPUT_BYTES limit to prevent memory exhaustion or token explosion."""
        if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
            return output[:MAX_OUTPUT_BYTES] + "\n... [TRUNCATED: Output exceeded size limit]"
        return output

    @abc.abstractmethod
    def execute(self, target: str, params: Optional[Dict[str, Any]] = None, scope: Optional[ScopeConfig] = None) -> ToolResult:
        """Executes the tool with validated parameters and returns a structured ToolResult."""
        pass
