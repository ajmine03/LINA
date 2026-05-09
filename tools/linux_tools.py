import subprocess

SAFE_COMMANDS = {
    "check storage": "df -h",
    "show storage": "df -h",
    "check memory": "free -h",
    "show memory": "free -h",
    "who am i": "whoami",
    "current directory": "pwd",
    "list files": "ls",
    "list downloads": "ls ~/Downloads",
    "open firefox": "firefox",
}


DANGEROUS_COMMANDS = {
    "update system": "sudo apt update && sudo apt upgrade -y",
    "shutdown pc": "sudo shutdown now",
    "reboot pc": "sudo reboot",
}


def execute_command(command):
    try:
        result = subprocess.check_output(
            command,
            shell=True,
            text=True,
            stderr=subprocess.STDOUT
        )

        return result

    except subprocess.CalledProcessError as e:
        return e.output
