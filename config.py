"""
Configuration module for LINA Security Testing Agent.
Supports environment variables and safe defaults.
"""

import os
import platform
import shutil
from pathlib import Path

# Base Paths
VERSION = "2.0.0"
BASE_DIR = Path(__file__).resolve().parent
RUNS_DIR = BASE_DIR / "runs"
REPORTS_DIR = BASE_DIR / "reports"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"

# Ensure runtime directories exist
RUNS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)

# OS & Environment
CURRENT_OS = platform.system()  # 'Linux', 'Darwin', 'Windows'
IS_LINUX = CURRENT_OS == "Linux"
IS_WINDOWS = CURRENT_OS == "Windows"
IS_MACOS = CURRENT_OS == "Darwin"

# Ollama / LLM Settings
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = os.getenv("LINA_MODEL", "qwen2.5:3b")
LLM_TEMPERATURE = float(os.getenv("LINA_TEMPERATURE", "0.2"))
LLM_TIMEOUT_SECONDS = int(os.getenv("LINA_LLM_TIMEOUT", "60"))

# Execution & Safety Boundaries
MAX_AGENT_STEPS = int(os.getenv("LINA_MAX_STEPS", "10"))
DEFAULT_TOOL_TIMEOUT = int(os.getenv("LINA_TOOL_TIMEOUT", "30"))
MAX_OUTPUT_BYTES = int(os.getenv("LINA_MAX_OUTPUT_BYTES", str(50 * 1024)))  # 50 KB
MAX_LLM_RETRY = 1  # Reformat retry count for malformed outputs

# Tool binary availability
NMAP_AVAILABLE = shutil.which("nmap") is not None
