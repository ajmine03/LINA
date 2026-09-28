"""
Bounded Security Orchestration Loop for LINA.
Coordinates scope validation, structured planning, policy guardrails,
tool execution, evidence analysis, and report generation.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, Optional

from config import DEFAULT_MODEL, MAX_AGENT_STEPS
from agent.analyzer import EvidenceAnalyzer
from agent.memory import RunMemory
from agent.planner import Planner
from agent.policy import PolicyEngine
from agent.scope import ScopeConfig
from tools.base import BaseTool, ToolResult
from tools.dns_lookup import DNSLookupTool
from tools.http_probe import HTTPProbeTool
from tools.nmap import NmapTool
from tools.report import ReportGeneratorTool
from tools.tls_check import TLSCheckTool


class SecurityOrchestrator:
    def __init__(
        self,
        scope: ScopeConfig,
        interactive: bool = True,
        max_steps: int = MAX_AGENT_STEPS,
        model: str = DEFAULT_MODEL
    ):
        self.scope = scope
        self.interactive = interactive
        self.max_steps = max_steps

        # Subsystems
        self.policy = PolicyEngine(auto_approve_passive=True, require_approval_for_active=True)
        self.analyzer = EvidenceAnalyzer()
        self.planner = Planner(model=model)

        # Tool Registry
        self.tools: Dict[str, BaseTool] = {
            "dns_lookup": DNSLookupTool(),
            "http_probe": HTTPProbeTool(),
            "tls_check": TLSCheckTool(),
            "nmap": NmapTool(),
            "report": ReportGeneratorTool(),
        }

    def run(self, target: str) -> RunMemory:
        """
        Executes the bounded security assessment loop on the authorized target.
        """
        memory = RunMemory(target=target, scope=self.scope)

        # 1. Scope Enforcement Gate
        in_scope, reason = self.scope.is_in_scope(target)
        if not in_scope:
            err_msg = f"Target '{target}' is OUT OF SCOPE. Refusing execution. Reason: {reason}"
            memory.stop_reason = err_msg
            memory.log_action(
                tool_name="scope_gate",
                parameters={"target": target},
                approved=False,
                approval_reason=err_msg
            )
            print(f"\n❌ [SCOPE ERROR] {err_msg}")
            return memory

        print(f"\n🚀 [LINA] Starting authorized security assessment for: {target}")
        print(f"📋 Scope: {self.scope.name} | Max steps: {self.max_steps}")

        executed_tool_names = []
        last_error = None

        # 2. Bounded Planning & Execution Loop
        while memory.step_count < self.max_steps:
            memory.step_count += 1
            step_idx = memory.step_count

            # Prepare summary for planner
            findings_summary = f"{len(memory.findings)} findings recorded so far."
            if memory.findings:
                sample_titles = [f["title"] for f in memory.findings[:3]]
                findings_summary += f" Recent: {'; '.join(sample_titles)}"

            print(f"\n--- [STEP {step_idx}/{self.max_steps}] Planning ---")
            step = self.planner.plan_next_step(
                target=target,
                step_number=step_idx,
                executed_tools=executed_tool_names,
                findings_summary=findings_summary,
                last_error=last_error
            )

            print(f"💡 Planner Reasoning: {step.thought}")

            # Check stop conditions
            if step.stop or step.tool_name in ("stop", "report"):
                memory.stop_reason = step.stop_reason or "Testing completed by planner."
                print(f"🛑 Stop condition met: {memory.stop_reason}")
                break

            tool_name = step.tool_name
            tool_params = step.parameters or {}
            # Ensure target is bound to approved target if missing or altered
            tool_target = tool_params.get("target", target)

            # Re-check scope for step target
            tool_in_scope, scope_reason = self.scope.is_in_scope(tool_target)
            if not tool_in_scope:
                print(f"⚠ Proposed target '{tool_target}' is outside scope ({scope_reason}). Skipping step.")
                memory.log_action(tool_name, tool_params, approved=False, approval_reason=scope_reason)
                last_error = f"Target {tool_target} outside scope."
                continue

            # 3. Policy Validation Gate
            policy_valid, policy_reason = self.policy.validate_tool_call(tool_name, tool_params)
            if not policy_valid:
                print(f"❌ [POLICY VIOLATION] Tool call rejected: {policy_reason}")
                memory.log_action(tool_name, tool_params, approved=False, approval_reason=policy_reason)
                last_error = f"Policy violation: {policy_reason}"
                continue

            # 4. Human Approval Gate
            approved, approval_reason = self.policy.request_approval(
                tool_name=tool_name,
                target=tool_target,
                params=tool_params,
                interactive=self.interactive
            )

            if not approved:
                print(f"🚫 Action '{tool_name}' not approved: {approval_reason}")
                memory.log_action(tool_name, tool_params, approved=False, approval_reason=approval_reason)
                last_error = f"User did not approve {tool_name}."
                continue

            # 5. Tool Execution
            tool = self.tools.get(tool_name)
            if not tool:
                print(f"❌ Tool '{tool_name}' not implemented.")
                continue

            print(f"⚙ Executing tool: {tool_name} on {tool_target}...")
            tool_result = tool.execute(tool_target, params=tool_params, scope=self.scope)

            executed_tool_names.append(tool_name)
            last_error = tool_result.error if not tool_result.success else None

            # 6. Evidence Analysis
            new_findings = self.analyzer.analyze(tool_result)
            memory.add_findings(new_findings)

            # Record in immutable audit log
            memory.log_action(
                tool_name=tool_name,
                parameters=tool_params,
                approved=True,
                approval_reason=approval_reason,
                tool_result=tool_result
            )

            if new_findings:
                print(f"🔍 Discovered {len(new_findings)} evidence-backed observation(s):")
                for f in new_findings:
                    print(f"   • [{f['severity']}] {f['title']}")

        # 7. Final Report Generation
        print(f"\n📊 Compiling final security assessment report...")
        report_tool = ReportGeneratorTool()
        report_res = report_tool.execute(
            target=target,
            params={
                "run_id": memory.run_id,
                "executive_summary": (
                    f"Automated non-destructive security testing completed on authorized target {target}. "
                    f"A total of {len(memory.findings)} findings and observations were documented with verifiable evidence."
                ),
                "findings": memory.findings,
                "evidence_timeline": [entry.model_dump() for entry in memory.audit_entries]
            },
            scope=self.scope
        )

        print(report_res.raw_output)
        return memory
