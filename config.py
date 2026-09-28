"""
Configuration module for LINA Security Testing Agent.
Supports environment variables, dynamic Ollama model detection, and safe defaults.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import List, Tuple
import httpx

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

# Priority list for auto-selecting local LLM
CANDIDATE_MODELS = [
    "qwen2.5-coder:7b",
    "llama3.1:8b",
    "qwen2.5:7b",
    "qwen2.5:3b",
    "llama3.1:latest",
    "qwen2.5-coder:latest",
]

DEFAULT_EMBEDDING_MODEL = os.getenv("LINA_EMBEDDING_MODEL", "nomic-embed-text:latest")


def detect_installed_models(host: str = OLLAMA_HOST) -> Tuple[List[str], List[str]]:
    """Queries local Ollama to list installed LLM models and embedding models."""
    try:
        with httpx.Client(trust_env=False, timeout=2.0) as client:
            res = client.get(f"{host}/api/tags")
            if res.status_code == 200:
                names = [m.get("name", "") for m in res.json().get("models", [])]
                llms = [n for n in names if not ("embed" in n or "bge" in n)]
                embeds = [n for n in names if "embed" in n or "bge" in n]
                return llms, embeds
    except Exception:
        pass
    return [], []


def get_default_model() -> str:
    """Selects the best available model from Ollama or environment variable."""
    explicit = os.getenv("LINA_MODEL")
    if explicit:
        return explicit

    llms, _ = detect_installed_models()
    for candidate in CANDIDATE_MODELS:
        for installed in llms:
            if candidate == installed or installed.startswith(candidate.split(":")[0]):
                return installed

    # Fallback to the first available LLM, or user-preferred default
    if llms:
        return llms[0]
    return "qwen2.5-coder:7b"


DEFAULT_MODEL = get_default_model()
LLM_TEMPERATURE = float(os.getenv("LINA_TEMPERATURE", "0.2"))
LLM_TIMEOUT_SECONDS = int(os.getenv("LINA_LLM_TIMEOUT", "60"))

# Execution & Safety Boundaries
MAX_AGENT_STEPS = int(os.getenv("LINA_MAX_STEPS", "10"))
DEFAULT_TOOL_TIMEOUT = int(os.getenv("LINA_TOOL_TIMEOUT", "30"))
MAX_OUTPUT_BYTES = int(os.getenv("LINA_MAX_OUTPUT_BYTES", str(50 * 1024)))  # 50 KB
MAX_LLM_RETRY = 1  # Reformat retry count for malformed outputs

# Tool binary availability
NMAP_AVAILABLE = shutil.which("nmap") is not None
