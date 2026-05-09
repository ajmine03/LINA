import os
import re
import subprocess

from ollama import chat


# =========================
# LINA CONFIG
# =========================

MODEL_NAME = "qwen2.5:3b"
MAX_HISTORY = 20

SYSTEM_PROMPT = """
You are LINA.

LINA = Linux Intelligent Native Assistant.

You are a real local Linux AI operating assistant running on Ubuntu.

Your job:
- understand natural language,
- understand typos,
- generate Linux commands when needed,
- explain Linux outputs naturally,
- reply briefly,
- act like an intelligent assistant,
- never mention cloud AI.

IMPORTANT RULES FOR COMMANDS:

1. When a Linux command is needed, ALWAYS format it EXACTLY like this:

COMMAND: <linux command>

2. NEVER split cd + another command into two separate COMMAND lines.
   cd does not persist between separate commands.
   Instead, use the full path directly, or chain with &&.

   WRONG:
   COMMAND: cd ~/Downloads
   COMMAND: ls

   CORRECT:
   COMMAND: ls ~/Downloads

   CORRECT (when chaining is truly needed):
   COMMAND: cd ~/Downloads && ls

3. Always prefer absolute or ~ paths over bare cd commands.

Examples:

COMMAND: df -h
COMMAND: ls ~/Downloads
COMMAND: ls -lh ~/Documents
COMMAND: mkdir -p ~/projects/new && ls ~/projects
COMMAND: sudo apt update
COMMAND: firefox

Never execute commands yourself.
Only suggest them.
"""

# =========================
# COLORS (ANSI)
# =========================

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"

def c(color, text):
    return f"{color}{text}{C.RESET}"

# =========================
# DANGEROUS COMMAND DETECTION
# =========================

DANGEROUS_PATTERNS = [
    r"\bsudo\b",
    r"\brm\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bchmod\b",
    r"\bchown\b",
    r"\bkill\b",
    r"\bapt\s+remove\b",
    r"\bapt\s+purge\b",
    r"\bpkill\b",
    r"\bsystemctl\s+stop\b",
    r"\bsystemctl\s+disable\b",
    r">\s*/dev/",
    r"\bformat\b",
    r"\bfdisk\b",
    r"\bparted\b",
    r"\bmv\s+/",
]

def is_dangerous(command):
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            return True
    return False

def danger_reason(command):
    labels = {
        r"\bsudo\b":               "runs with root privileges",
        r"\brm\b":                 "deletes files/directories",
        r"\bshutdown\b":           "shuts down the system",
        r"\breboot\b":             "reboots the system",
        r"\bmkfs\b":               "formats a filesystem",
        r"\bdd\b":                 "raw disk write — very destructive",
        r"\bchmod\b":              "changes file permissions",
        r"\bchown\b":              "changes file ownership",
        r"\bkill\b":               "kills a running process",
        r"\bapt\s+remove\b":       "removes installed packages",
        r"\bapt\s+purge\b":        "purges packages and config",
        r"\bpkill\b":              "kills processes by name",
        r"\bsystemctl\s+stop\b":   "stops a system service",
        r"\bsystemctl\s+disable\b":"disables a system service",
        r">\s*/dev/":              "writes directly to a device",
        r"\bformat\b":             "may format storage",
        r"\bfdisk\b":              "modifies disk partitions",
        r"\bparted\b":             "modifies disk partitions",
        r"\bmv\s+/":               "moves files from root path",
    }
    reasons = []
    for pattern, reason in labels.items():
        if re.search(pattern, command):
            reasons.append(reason)
    return ", ".join(reasons) if reasons else "potentially dangerous"

# =========================
# INTERACTIVE COMMAND DETECTION
# =========================

INTERACTIVE_PATTERNS = [
    r"\bfirefox\b", r"\bchromium\b", r"\bgedit\b", r"\bnano\b", r"\bvim\b",
    r"\bvi\b", r"\bemacs\b", r"\btop\b", r"\bhtop\b", r"\bbtop\b",
    r"\bnautilus\b", r"\bthunderbird\b", r"\bvlc\b", r"\bgimp\b",
    r"\bcode\b", r"\bxterm\b", r"\bgnome-terminal\b", r"\bxdg-open\b",
    r"\bless\b", r"\bmore\b", r"\bman\b", r"\bwatch\b", r"\bssh\b",
    r"\bping\b", r"\btail\s+-f\b", r"\bjournalctl\s+-f\b",
]

def is_interactive(command):
    return any(re.search(p, command) for p in INTERACTIVE_PATTERNS)

# =========================
# CD TRACKING
# Fix: if AI still sends a bare "cd <path>", apply it in Python too
# so subsequent commands run in the right directory.
# =========================

def apply_cd_if_needed(command):
    """
    If the command is purely a cd, apply it to the Python process CWD.
    Returns True if it was a pure cd (no need to run in subprocess).
    """
    stripped = command.strip()
    match = re.fullmatch(r"cd\s+(.*)", stripped)
    if match:
        path = match.group(1).strip().replace("~", os.path.expanduser("~"))
        try:
            os.chdir(path)
            return True, f"Changed directory to: {os.getcwd()}"
        except FileNotFoundError:
            return True, f"Directory not found: {path}"
        except Exception as e:
            return True, str(e)
    return False, None

# =========================
# COMMAND EXECUTION
# =========================

def run_command(command):
    """
    Route command to the right execution strategy.
    Ctrl+C always stops the child and returns control to LINA.
    """
    # Handle bare cd in Python directly
    was_cd, cd_output = apply_cd_if_needed(command)
    if was_cd:
        return True, cd_output

    if is_interactive(command):
        try:
            subprocess.run(command, shell=True, text=True, cwd=os.getcwd())
            return True, "(interactive command — no output captured)"
        except KeyboardInterrupt:
            print()
            return False, "(interrupted by user)"
        except Exception as e:
            return False, str(e)

    try:
        output = subprocess.check_output(
            command,
            shell=True,
            text=True,
            stderr=subprocess.STDOUT,
            timeout=30,
            cwd=os.getcwd()
        )
        return True, output

    except KeyboardInterrupt:
        print()
        return False, "(interrupted by user)"

    except subprocess.CalledProcessError as e:
        return False, e.output or "(command failed with no output)"

    except subprocess.TimeoutExpired:
        return False, "Command timed out after 30 seconds."

    except Exception as e:
        return False, str(e)

# =========================
# UTILITIES
# =========================

def clear_screen():
    os.system("clear")

def print_header():
    print(c(C.CYAN, "╔══════════════════════════════════════╗"))
    print(c(C.CYAN, "║") + c(C.BOLD + C.WHITE, "         LINA v1.1                    ") + c(C.CYAN, "║"))
    print(c(C.CYAN, "║") + c(C.DIM,  "  Linux Intelligent Native Assistant  ") + c(C.CYAN, "║"))
    print(c(C.CYAN, "╚══════════════════════════════════════╝"))
    print()

def print_divider():
    print(c(C.DIM, "──────────────────────────────────────"))

def trim_conversation(conversation, max_turns=MAX_HISTORY):
    if len(conversation) > max_turns * 2:
        conversation = conversation[-(max_turns * 2):]
    return conversation

def explain_output(user_request, command, output):
    explain_prompt = f"""
User request: {user_request}
Linux command: {command}
Linux output:
{output}

Explain this naturally and briefly.
"""
    stream = chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": "You are LINA. Explain Linux outputs briefly and clearly."},
            {"role": "user",   "content": explain_prompt}
        ],
        stream=True
    )
    print(c(C.MAGENTA, "\n💬 LINA: "), end="", flush=True)
    for chunk in stream:
        print(chunk["message"]["content"], end="", flush=True)
    print("\n")

def handle_command(command, user_input, index=None, total=None):
    label = ""
    if index is not None and total and total > 1:
        label = f" [{index}/{total}]"

    print_divider()
    print(c(C.CYAN, f"⚙  Detected command{label}:"))
    print(c(C.BOLD + C.WHITE, f"   {command}"))
    print()

    if is_dangerous(command):
        reason = danger_reason(command)
        print(c(C.RED, f"⚠  WARNING: This command {reason}."))
        print(c(C.YELLOW, "   Proceed with caution.\n"))

    confirm = input(c(C.YELLOW, "   Execute? (y/n): ")).strip().lower()

    if confirm not in ["y", "yes"]:
        print(c(C.DIM, "   Command skipped.\n"))
        return

    print(c(C.GREEN, "\n▶  Running...\n"))

    success, output = run_command(command)

    if output:
        print(c(C.DIM, output))

    if not success:
        print(c(C.RED, "   Command returned an error.\n"))

    explain_output(user_input, command, output or "(no output)")

# =========================
# MAIN LOOP
# =========================

conversation = []
message_count = 0

clear_screen()
print_header()
print(c(C.DIM, "Type 'exit' to quit, 'clear' to reset screen.\n"))

while True:

    message_count += 1

    if message_count > 1 and message_count % 10 == 0:
        clear_screen()
        print_header()

    try:
        user_input = input(c(C.GREEN + C.BOLD, "You: ")).strip()
    except KeyboardInterrupt:
        print(c(C.DIM, "  (type 'exit' to quit)"))
        continue
    except EOFError:
        print(c(C.DIM, "\n\nGoodbye!\n"))
        break

    if not user_input:
        continue

    if user_input.lower() == "exit":
        print(c(C.DIM, "\nGoodbye!\n"))
        break

    if user_input.lower() == "clear":
        clear_screen()
        print_header()
        message_count = 0
        continue

    if user_input.lower() == "history":
        print(c(C.DIM, f"\n{len(conversation) // 2} turns in memory.\n"))
        continue

    conversation.append({"role": "user", "content": user_input})
    conversation = trim_conversation(conversation)

    stream = chat(
        model=MODEL_NAME,
        messages=[{"role": "system", "content": SYSTEM_PROMPT}] + conversation,
        stream=True
    )

    print(c(C.MAGENTA, "\nLINA: "), end="", flush=True)

    full_reply = ""

    for chunk in stream:
        content = chunk["message"]["content"]
        full_reply += content
        print(content, end="", flush=True)

    print("\n")

    conversation.append({"role": "assistant", "content": full_reply})

    commands = re.findall(r"COMMAND:\s*(.+)", full_reply)

    if not commands:
        continue

    total = len(commands)

    for i, command in enumerate(commands, start=1):
        command = command.strip()
        if command:
            handle_command(command, user_input, index=i, total=total)
