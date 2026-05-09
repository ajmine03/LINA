# LINA

Linux Intelligent Native Assistant

A local open-source AI operating assistant for Linux.

LINA is designed to behave like a real AI assistant instead of a hardcoded command bot.
It runs locally using Ollama and Linux tools, understands natural language, generates terminal commands dynamically, explains command outputs, and interacts conversationally.

---

# Features

## Local AI Runtime

* Fully local AI using Ollama
* Offline capable
* Privacy-focused
* No cloud dependency required after model download

## Conversational Linux Assistant

* Natural language interaction
* Streaming AI responses
* Context-aware conversation
* Short intelligent replies

## AI-Generated Linux Commands

Examples:

```text
install vscode
check storage
list downloads
remove firefox
open firefox
```

LINA dynamically generates Linux terminal commands using the local LLM.

---

# Current Capabilities

* AI-generated Linux commands
* Dangerous command detection
* Confirmation before execution
* AI explanation of terminal outputs
* Auto screen clearing
* Conversational fallback AI
* Local execution engine
* Streaming responses

---

# Example

```text
You: check my storage
```

LINA:

```text
COMMAND: df -h
```

Then:

```text
Execute command? (y/n)
```

After execution:

```text
LINA Explanation:
Your Linux partition has around 81 GB free space remaining.
```

---

# Architecture

```text
User
 ↓
LINA
 ↓
Ollama Local LLM
 ↓
AI-generated Linux command
 ↓
Safety confirmation
 ↓
Linux execution
 ↓
AI explanation layer
```

---

# Tech Stack

* Python
* Ollama
* Qwen2.5
* Linux Terminal
* subprocess
* Regex command extraction

---

# Installation

## Clone Repository

```bash
git clone https://github.com/ajmine03/LINA.git
```

## Enter Project

```bash
cd LINA
```

## Create Virtual Environment

```bash
python3 -m venv venv
```

## Activate Virtual Environment

```bash
source venv/bin/activate
```

## Install Dependencies

```bash
venv/bin/pip install -r requirements.txt
```

---

# Install Ollama

Official Website:

[https://ollama.com](https://ollama.com)

Linux install:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

---

# Download AI Model

Recommended:

```bash
ollama run qwen2.5:3b
```

---

# Run LINA

```bash
venv/bin/python assistant.py
```

---

# Safety Philosophy

LINA NEVER:

* stores passwords
* bypasses sudo
* silently executes dangerous commands

Linux itself handles authentication.

LINA handles:

* reasoning
* command generation
* assistant behavior
* output explanation

---
<img width="1536" height="1024" alt="ChatGPT Image May 10, 2026, 02_17_23 AM" src="https://github.com/user-attachments/assets/a7729e41-4ef7-4429-8685-7c07356df144" />
<img width="1536" height="1024" alt="ChatGPT Image May 10, 2026, 02_20_56 AM" src="https://github.com/user-attachments/assets/f01cfb8a-c4dd-43cc-a348-02ee7ab7345a" />
<img width="1536" height="1024" alt="ChatGPT Image May 10, 2026, 02_24_14 AM" src="https://github.com/user-attachments/assets/0c059ef3-042f-4fd8-9f97-b61c81dbb4e2" />

# screenshorts from version v0.6 - Alpha
# Current Version

```text
LINA v0.6-alpha
```

Current focus:

* AI operating assistant architecture
* Linux integration
* execution engine
* conversational UX

---

# Roadmap

## v0.7

* intelligent execution engine
* async terminal handling
* live command streaming
* better sudo handling
* process cancellation

## v0.8

* file understanding
* code summarization
* project analysis
* file editing

## v0.9

* memory system
* persistent context
* preference learning

## v1.0

* real Linux AI agent
* autonomous workflows
* multi-step planning
* advanced tool orchestration

---

# Vision

```text
Local.
Private.
Open-source.
Linux-native.
AI-first.
```

---

# Disclaimer

LINA is an experimental AI operating assistant.
AI-generated Linux commands can be dangerous.
Always review commands before execution.

---

# License

MIT License

---

# Repository

[https://github.com/ajmine03/LINA](https://github.com/ajmine03/LINA)
