import ast
import re
from typing import List, Dict, Any


def detect_command_injection(tree: ast.AST, source: str, filename: str) -> List[Dict[str, Any]]:
    """Detect command injection (unsafe subprocess calls)."""
    findings = []

    patterns = [
        (r"os\.system\s*\(.*?\)", "os.system() with user input is dangerous"),
        (
            r"subprocess\.call\s*\(.*?shell\s*=\s*True",
            "subprocess.call() with shell=True (command injection risk)",
        ),
        (
            r"subprocess\.Popen\s*\(.*?shell\s*=\s*True",
            "subprocess.Popen() with shell=True (command injection risk)",
        ),
        (r"eval\s*\(.*?\)", "eval() of user-controlled input (command injection risk)"),
        (r"exec\s*\(.*?\)", "exec() of user-controlled input (command injection risk)"),
        (r"__import__\s*\(.*?\)", "Dynamic import with user input (risky)"),
    ]

    for pattern, msg in patterns:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line_no = source[: match.start()].count("\n") + 1
            lines = source.split("\n")
            context = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(
                {
                    "type": "command_injection",
                    "severity": "Critical",
                    "line": line_no,
                    "code": context.strip(),
                    "message": f"Command Injection: {msg}",
                    "fix": "Protocol: Argument Separation. Set 'shell=False' in subprocess execution calls (such as subprocess.run, call, Popen). Pass commands and arguments as a list of strings rather than a single interpolated command string. Example: Change subprocess.run(f'ping -c 1 {ip}', shell=True) to subprocess.run(['ping', '-c', '1', ip], shell=False).",
                }
            )

    return findings
