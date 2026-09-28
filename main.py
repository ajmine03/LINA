#!/usr/bin/env python3
"""
LINA (Linux Intelligent Native Assistant)
Local-First, Terminal-Based AI Security Testing Agent.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import httpx

from config import (
    CURRENT_OS,
    DEFAULT_MODEL,
    KNOWLEDGE_DIR,
    MAX_AGENT_STEPS,
    NMAP_AVAILABLE,
    OLLAMA_HOST,
    REPORTS_DIR,
    RUNS_DIR,
)
from agent.knowledge import KnowledgeBase
from agent.orchestrator import SecurityOrchestrator
from agent.policy import ActionRisk, PolicyEngine
from agent.scope import ScopeConfig


def print_banner():
    banner = r"""
  _      _____ _   _          
 | |    |_   _| \ | |   /\    
 | |      | | |  \| |  /  \   
 | |      | | | . ` | / /\ \  
 | |____ _| |_| |\  |/ ____ \ 
 |______|_____|_| \_/_/    \_\
    """
    print(f"\033[96m{banner}\033[0m")
    print("\033[1m\033[97m  Local-First AI Security Testing & Auditing Agent\033[0m")
    print(f"\033[2m  OS: {CURRENT_OS} | Engine: Ollama ({DEFAULT_MODEL})\033[0m\n")


def cmd_status(args):
    """Checks the status of the local environment, Ollama, and tool binaries."""
    print("=== LINA System & Environment Status ===\n")
    print(f"Operating System:    {CURRENT_OS}")
    print(f"Ollama Endpoint:     {OLLAMA_HOST}")
    print(f"Configured Model:    {DEFAULT_MODEL}")
    print(f"Nmap Available:      {'Yes (/usr/bin/nmap)' if NMAP_AVAILABLE else 'No (Passive mode only)'}")
    print(f"Runs Directory:      {RUNS_DIR}")
    print(f"Reports Directory:   {REPORTS_DIR}")

    # Check Ollama connectivity
    print("\nChecking Ollama daemon...")
    try:
        with httpx.Client(trust_env=False, timeout=3.0) as client:
            resp = client.get(f"{OLLAMA_HOST}/api/tags")
            if resp.status_code == 200:
                models = [m.get("name") for m in resp.json().get("models", [])]
                print(f"✅ Ollama is ONLINE. Available local models: {', '.join(models) if models else 'None'}")
                if any(DEFAULT_MODEL in m for m in models):
                    print(f"   Model '{DEFAULT_MODEL}' is ready.")
                else:
                    print(f"   ⚠ Configured model '{DEFAULT_MODEL}' not found. Run: ollama pull {DEFAULT_MODEL}")
            else:
                print(f"⚠ Ollama responded with HTTP status {resp.status_code}.")
    except Exception as e:
        print(f"❌ Ollama is OFFLINE or unreachable: {e}")
        print("   (LINA will operate in deterministic fallback mode if needed).")


def cmd_tools(args):
    """Lists all available security testing tools and their guardrail policies."""
    print("=== Registered LINA Security Tools ===\n")
    policy = PolicyEngine()
    orchestrator = SecurityOrchestrator(scope=ScopeConfig(name="dummy"))

    for name, tool in orchestrator.tools.items():
        risk = policy.categorize_action(name)
        risk_color = "\033[92m" if risk == ActionRisk.PASSIVE else "\033[93m"
        print(f"• \033[1m{name}\033[0m  [{risk_color}{risk.value}\033[0m]")
        print(f"    Description:    {tool.description}")
        print(f"    Requires Scope: {tool.requires_scope}")
        print(f"    Active Probe:   {tool.is_active}")
        print()


def cmd_scan(args):
    """Runs an authorized security testing scan against the specified target."""
    target = args.target.strip()
    if not target:
        print("Error: Target cannot be empty.")
        sys.exit(1)

    # Load or generate scope
    if args.scope:
        scope_path = Path(args.scope)
        if not scope_path.exists():
            print(f"Error: Scope file not found: {scope_path}")
            sys.exit(1)
        try:
            scope = ScopeConfig.from_file(scope_path)
        except Exception as e:
            print(f"Error parsing scope file: {e}")
            sys.exit(1)
    else:
        # Prompt user to explicitly confirm authorized single target
        print("\n" + "=" * 60)
        print("⚠ NO SCOPE FILE SPECIFIED")
        print(f"You are about to test target: \033[1m{target}\033[0m")
        print("You MUST own this target or possess explicit written authorization.")
        print("=" * 60)
        try:
            confirm = input("Do you confirm authorization for this exact target? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Refusing scan: Target authorization not confirmed.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

        scope = ScopeConfig.from_single_target(target)

    orchestrator = SecurityOrchestrator(
        scope=scope,
        interactive=not args.non_interactive,
        max_steps=args.max_steps,
        model=args.model or DEFAULT_MODEL
    )

    memory = orchestrator.run(target)
    print("\nAssessment finished.")
    print(f"Findings recorded: {len(memory.findings)}")
    print(f"Audit log saved to: {memory.audit_file}")


def cmd_report(args):
    """Displays or locates a report by run ID."""
    run_id = args.run_id.strip()
    md_file = REPORTS_DIR / f"{run_id}_report.md"
    json_file = REPORTS_DIR / f"{run_id}_report.json"

    if not md_file.exists() and not json_file.exists():
        print(f"No reports found for run ID: '{run_id}' in {REPORTS_DIR}")
        # List available reports
        available = list(REPORTS_DIR.glob("*_report.md"))
        if available:
            print("\nAvailable reports:")
            for p in available:
                print(f"  • {p.stem.replace('_report', '')}")
        return

    if md_file.exists():
        print(f"=== Markdown Report: {md_file} ===\n")
        with open(md_file, "r", encoding="utf-8") as f:
            print(f.read())
    elif json_file.exists():
        print(f"=== JSON Report: {json_file} ===\n")
        with open(json_file, "r", encoding="utf-8") as f:
            print(f.read())


def cmd_knowledge(args):
    """Knowledge base search and listing."""
    kb = KnowledgeBase()
    if args.action == "search":
        if not args.query:
            print("Error: Please provide a query to search.")
            return
        results = kb.search(args.query)
        print(f"Found {len(results)} lesson(s) matching '{args.query}':\n")
        for idx, item in enumerate(results, start=1):
            print(f"[{idx}] {item.get('challenge_id', 'N/A')} - {item.get('category', 'general')}")
            print(f"    Observation: {item.get('observations')}")
            print(f"    Lesson:      {item.get('reusable_lesson')}")
            print(f"    Remediation: {item.get('explanation')}")
            print(f"    Limitations: {item.get('limitations')}")
            print()
    elif args.action == "list":
        lessons = kb.load_lessons()
        print(f"Knowledge Base contains {len(lessons)} vetted lesson(s):\n")
        for item in lessons:
            print(f"• [{item.get('challenge_id')}] ({item.get('category')}) {item.get('reusable_lesson')}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="lina",
        description="LINA: Local-First AI Security Testing & Auditing Agent"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run an authorized security assessment")
    scan_parser.add_argument("target", help="Target IP, hostname, or URL to assess")
    scan_parser.add_argument("--scope", "-s", help="Path to JSON scope authorization file", default=None)
    scan_parser.add_argument("--max-steps", "-m", type=int, default=MAX_AGENT_STEPS, help=f"Max loop steps (default: {MAX_AGENT_STEPS})")
    scan_parser.add_argument("--model", help=f"Ollama model name (default: {DEFAULT_MODEL})", default=DEFAULT_MODEL)
    scan_parser.add_argument("--non-interactive", action="store_true", help="Run without interactive confirmation prompts")

    # Command: status
    subparsers.add_parser("status", help="Check local environment, Ollama, and tool availability")

    # Command: tools
    subparsers.add_parser("tools", help="List registered security tools and policy risk levels")

    # Command: report
    report_parser = subparsers.add_parser("report", help="View security assessment report")
    report_parser.add_argument("run_id", help="Run ID of the report to display")

    # Command: knowledge
    kb_parser = subparsers.add_parser("knowledge", help="Search or list vetted CTF/security lessons")
    kb_subparsers = kb_parser.add_subparsers(dest="action", help="Knowledge action")
    kb_search_parser = kb_subparsers.add_parser("search", help="Search lessons by keyword")
    kb_search_parser.add_argument("query", help="Keyword or category to search for")
    kb_subparsers.add_parser("list", help="List all vetted lessons")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "status":
        cmd_status(args)
    elif args.command == "tools":
        cmd_tools(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "knowledge":
        cmd_knowledge(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
