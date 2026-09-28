# LINA (Linux Intelligent Native Assistant)

**Local-First, Terminal-Based AI Security Testing Agent & Operating Assistant**

LINA is an open-source, local-first security testing and auditing agent designed to help developers, systems administrators, and security professionals assess their authorized infrastructure. Powered locally by [Ollama](https://ollama.com) (defaulting to `qwen2.5:3b`), LINA enforces strict scope boundaries, requires human-in-the-loop approval before active actions, utilizes only non-destructive tools, and produces evidence-backed assessment reports.

> [!IMPORTANT]
> **Authorized-Use Policy & Legal Disclaimer**:
> LINA must only be used against IP addresses, domains, and systems that you own or have explicit, prior written authorization to test. LINA is designed strictly for defensive assessment and hardening. It is **not** an unrestricted attack tool and deliberately excludes exploitation payloads, brute force, credential stuffing, denial-of-service, stealth evasion, and persistence mechanisms.

---

## Architecture Overview

```
User Request / Target & Scope
             │
             ▼
   [Scope Validation Engine] ────────── Reject out-of-scope targets & redirects
             │
             ▼
   [Structured Planner (Ollama)] ────── Queries local LLM for safe next step
             │
             ▼
   [Policy & Safety Guardrails] ─────── Enforces argument whitelist & checks
             │
             ▼
   [Human Approval Gate] ────────────── Operator interactive confirmation (y/N)
             │
             ▼
   [Non-Destructive Tool Execution] ─── DNS / HTTP / TLS / Nmap (No shell=True)
             │
             ▼
   [Evidence-Based Analyzer] ────────── Separates observations from hypotheses
             │
             ▼
   [Audit Log & Final Report] ───────── Saves runs/<run_id>/ & reports/
```

### Directory Structure

```text
LINA/
├── main.py                     # CLI entrypoint (lina scan, tools, status, report, knowledge)
├── config.py                   # Global configuration, OS detection, and safety defaults
├── assistant.py                # Preserved classic conversational assistant (LINA v1.x)
├── agent/
│   ├── orchestrator.py         # Bounded agent loop (Plan -> Check -> Execute -> Analyze)
│   ├── planner.py              # Structured Ollama planning with Pydantic schemas & fallback
│   ├── policy.py               # Security policy, dangerous argument checks, approval gates
│   ├── scope.py                # Exact IP, CIDR, and domain scope validation engine
│   ├── analyzer.py             # Evidence vs. hypothesis analyzer & prompt-injection defense
│   ├── memory.py               # Immutable JSONL audit trail & session memory
│   └── knowledge.py            # CTF knowledge search & lesson retrieval engine
├── tools/
│   ├── base.py                 # Abstract BaseTool interface & ToolResult model
│   ├── dns_lookup.py           # Passive DNS resolution (A, AAAA, CNAME, PTR)
│   ├── http_probe.py           # HTTP metadata, security headers, and banner inspection
│   ├── tls_check.py            # TLS/SSL certificate validity, expiry, and cipher audit
│   ├── nmap.py                 # Non-destructive port discovery & service version enumeration
│   └── report.py               # Markdown and JSON assessment report generator
├── knowledge/
│   ├── README.md               # Knowledge base philosophy & prompt-injection warning
│   ├── methodology.md          # Security assessment phases and guidelines
│   └── lessons.jsonl           # Structured, vetted CTF lessons & hardening advice
├── runs/                       # Per-run execution logs and audit trails (audit.jsonl)
├── reports/                    # Generated Markdown and JSON reports
└── tests/                      # Comprehensive unit and integration test suite
```

---

## Features

### 1. Strict Scope Validation
- Supports exact IPv4/IPv6 addresses, CIDR blocks (e.g. `10.0.0.0/24`), and specific domains.
- Prevents out-of-scope redirection hijacking (e.g. HTTP 301/302 redirects leading to unapproved third-party hosts).

### 2. Guardrails & Approval Gates
- Strict whitelist of non-destructive assessment tools.
- Dangerous flags (such as `--script=exploit*`, `--script=dos*`, shell chaining characters `; | & $`) are blocked immediately.
- Active actions (e.g., HTTP probing, Nmap port scanning) require interactive operator confirmation (`[y/N]`).

### 3. Non-Destructive Toolset
- **`dns_lookup`**: Python native DNS querying without external binary dependencies.
- **`http_probe`**: Inspects server banners, missing security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`), and redirect chains.
- **`tls_check`**: Checks certificate issuer, SANs, days remaining until expiry, and supported SSL/TLS versions.
- **`nmap`**: Runs parameterized subprocess commands (never `shell=True`) limited to non-destructive port discovery (`-T3`, `--top-ports 100`, `--open`).
- **`report`**: Compiles findings into Markdown and JSON formats.

### 4. Evidence vs. Hypothesis Separation
- Findings clearly distinguish factual observations (e.g. "Server returned `nginx/1.18.0`") from hypotheses.
- Banners alone are never treated as confirmation of an exploitable vulnerability due to vendor security backports.

### 5. Local AI Runtime & Offline Resiliency
- Operates entirely locally with Ollama (no cloud API keys or telemetry).
- Deterministic fallback allows full security assessment even if Ollama is temporarily offline.

---

## Installation & Setup

### 1. Clone & Enter Repository
```bash
git clone https://github.com/ajmine03/LINA.git
cd LINA
```

### 2. Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Ollama and Download Model
Install Ollama from [ollama.com](https://ollama.com) or on Linux:
```bash
curl -fsSL https://ollama.com/install.sh | sh
```
Download the recommended local model:
```bash
ollama run qwen2.5:3b
```

---

## Configuration

LINA can be configured via environment variables:

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama daemon API endpoint |
| `LINA_MODEL` | `qwen2.5:3b` | Default Ollama model name |
| `LINA_MAX_STEPS` | `10` | Maximum bounded steps in agent loop |
| `LINA_TOOL_TIMEOUT` | `30` | Per-tool execution timeout in seconds |
| `LINA_MAX_OUTPUT_BYTES` | `51200` (50 KB) | Tool raw output truncation threshold |
| `LINA_TEMPERATURE` | `0.2` | Model temperature for deterministic planning |

---

## CLI Usage

### Check System Status
Verify local environment, Ollama connectivity, and tool availability:
```bash
python3 main.py status
```

### List Registered Tools
View all tools, descriptions, and policy risk levels (PASSIVE vs ACTIVE):
```bash
python3 main.py tools
```

### Run an Authorized Assessment
Scan an authorized target using a scope definition file:
```bash
python3 main.py scan 127.0.0.1 --scope tests/fixtures/test_scope.json
```

Or scan a single authorized host directly (prompts for authorization verification):
```bash
python3 main.py scan 127.0.0.1
```

Additional scan flags:
- `--max-steps 5`: Limits maximum agent steps.
- `--model qwen2.5:3b`: Specifies custom Ollama model.
- `--non-interactive`: Runs without interactive prompts (auto-skips active tools requiring confirmation).

### View Assessment Reports
Locate and view reports generated during a scan:
```bash
python3 main.py report <run_id>
```
Reports are stored permanently in `reports/<run_id>_report.md` and `reports/<run_id>_report.json`.

### Search CTF & Hardening Knowledge Base
Search structured security lessons and remediation patterns:
```bash
python3 main.py knowledge search "header"
python3 main.py knowledge list
```

---

## Scope File Format

Create a JSON scope file to define testing boundaries:

```json
{
  "name": "staging_environment_scope",
  "description": "Authorized staging servers audit",
  "allowed_ips": ["192.168.1.50"],
  "allowed_cidrs": ["10.10.0.0/24"],
  "allowed_domains": ["staging.internal.corp"],
  "allow_subdomains": false,
  "disallowed_targets": ["10.10.0.1"],
  "rate_limit_per_minute": 60
}
```

---

## Running the Test Suite

LINA includes comprehensive unit tests verifying scope enforcement, policy guardrails, tool execution, bounded loops, and prompt-injection defenses:

```bash
pytest -v tests/
```

Tests run completely offline and use local loopback fixtures without generating external network traffic.

---

## Classic Assistant Mode

The original conversational terminal assistant is preserved for backward compatibility:

```bash
python3 assistant.py
```

---

## License

This project is licensed under the [MIT License](LICENSE).
