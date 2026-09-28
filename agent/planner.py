"""
Structured Planner for LINA Security Testing Agent.
Uses local Ollama LLM to propose next steps in strict JSON format.
Treats model output as untrusted suggestions, with automatic reformatting retry
and deterministic fallback when Ollama is unavailable or returns invalid JSON.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel, Field

from config import DEFAULT_MODEL, LLM_TEMPERATURE, LLM_TIMEOUT_SECONDS, MAX_LLM_RETRY, OLLAMA_HOST
from agent.analyzer import sanitize_untrusted_text


class PlanStep(BaseModel):
    thought: str = Field(description="Reasoning behind selecting this non-destructive step.")
    tool_name: str = Field(description="Must be one of: dns_lookup, http_probe, tls_check, nmap, report, or stop.")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters for the selected tool.")
    stop: bool = Field(default=False, description="Set to true if testing goal is complete or no more tools needed.")
    stop_reason: Optional[str] = Field(default=None, description="Explanation if stopping.")


SYSTEM_PLANNER_PROMPT = """You are LINA's Security Testing Planner.
Your role: Plan the next NON-DESTRUCTIVE security testing step for an authorized target.

PERMITTED TOOLS ONLY:
- dns_lookup (target)
- http_probe (target, port, path, method)
- tls_check (target, port)
- nmap (target, ports, timing)
- report (summary)
- stop

STRICT RULES:
1. Suggest ONE next step at a time.
2. NEVER suggest exploits, brute-forcing, password cracking, SQL injection, DoS, or arbitrary shell commands.
3. If all appropriate passive and active checks are completed, set "stop": true or choose tool "report".
4. You MUST respond with ONLY a valid JSON object matching this schema:
{
  "thought": "Your analytical reasoning here",
  "tool_name": "dns_lookup",
  "parameters": {"target": "..." },
  "stop": false,
  "stop_reason": null
}
Do NOT include markdown fences, preambles, or conversational commentary.
"""


class Planner:
    def __init__(self, model: str = DEFAULT_MODEL, ollama_host: str = OLLAMA_HOST):
        self.model = model
        self.ollama_host = ollama_host.rstrip("/")

    def plan_next_step(
        self,
        target: str,
        step_number: int,
        executed_tools: List[str],
        findings_summary: str,
        last_error: Optional[str] = None
    ) -> PlanStep:
        """
        Queries Ollama for the next structured step.
        Falls back gracefully if LLM is unavailable or fails JSON validation.
        """
        prompt = f"""Target: {target}
Current Step: {step_number}
Tools already executed: {executed_tools}
Current findings summary:
{sanitize_untrusted_text(findings_summary, max_chars=1000)}
"""
        if last_error:
            prompt += f"\nLast tool error: {last_error}\n"

        prompt += "\nWhat is the next safe, permitted testing step? Provide ONLY valid JSON."

        for attempt in range(MAX_LLM_RETRY + 1):
            raw_response = self._call_ollama(prompt)
            if not raw_response:
                # LLM call failed or unavailable; use deterministic fallback
                return self._deterministic_fallback(target, executed_tools)

            parsed = self._parse_json_plan(raw_response)
            if parsed:
                return parsed

            # Retry with explicit reformatting instruction
            prompt += "\nERROR: Your previous response was not valid JSON. You MUST return strictly a raw JSON object."

        # If retries exhausted, safely fall back
        return self._deterministic_fallback(target, executed_tools)

    def _call_ollama(self, user_content: str) -> Optional[str]:
        """Calls local Ollama API via HTTP request."""
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PLANNER_PROMPT},
                {"role": "user", "content": user_content}
            ],
            "options": {
                "temperature": LLM_TEMPERATURE
            },
            "stream": False
        }
        try:
            with httpx.Client(trust_env=False, timeout=LLM_TIMEOUT_SECONDS) as client:
                res = client.post(url, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    return data.get("message", {}).get("content", "")
                return None
        except Exception:
            return None

    def _parse_json_plan(self, text: str) -> Optional[PlanStep]:
        """Extracts and validates JSON from model text."""
        # Strip potential markdown code blocks
        clean = text.strip()
        if "```" in clean:
            matches = re.findall(r"```(?:json)?\s*({[\s\S]*?})\s*```", clean)
            if matches:
                clean = matches[0]

        # Extract first JSON object
        json_match = re.search(r"({[\s\S]*})", clean)
        if json_match:
            clean = json_match.group(1)

        try:
            data = json.loads(clean)
            return PlanStep(**data)
        except Exception:
            return None

    def _deterministic_fallback(self, target: str, executed_tools: List[str]) -> PlanStep:
        """
        Deterministic, safe non-destructive security sequence
        when LLM is offline or output is unparseable.
        Sequence: dns_lookup -> http_probe -> tls_check -> report -> stop
        """
        if "dns_lookup" not in executed_tools and not target.replace(".", "").isdigit():
            return PlanStep(
                thought="Fallback: Initiating baseline DNS resolution.",
                tool_name="dns_lookup",
                parameters={"target": target},
                stop=False
            )
        elif "http_probe" not in executed_tools:
            return PlanStep(
                thought="Fallback: Probing HTTP service and security headers.",
                tool_name="http_probe",
                parameters={"target": target},
                stop=False
            )
        elif "tls_check" not in executed_tools:
            return PlanStep(
                thought="Fallback: Inspecting TLS certificate and protocol posture.",
                tool_name="tls_check",
                parameters={"target": target, "port": 443},
                stop=False
            )
        elif "report" not in executed_tools:
            return PlanStep(
                thought="Fallback: Assessment tools completed. Compiling final report.",
                tool_name="report",
                parameters={},
                stop=True,
                stop_reason="Standard non-destructive security suite completed."
            )
        else:
            return PlanStep(
                thought="Fallback: All actions completed.",
                tool_name="stop",
                stop=True,
                stop_reason="Completed."
            )
