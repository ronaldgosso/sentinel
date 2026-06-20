import ast
import re
from typing import List, Dict, Any


def detect_hardcoded_secrets(tree: ast.AST, source: str, filename: str) -> List[Dict[str, Any]]:
    """Detect hardcoded secrets (API keys, tokens, passwords)."""
    findings = []

    secret_patterns = [
        (
            r'(api_key|apikey|secret|password|token|private_key)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',
            "Hardcoded API key or secret",
        ),
        (
            r'(API_KEY|SECRET_KEY|PASSWORD)\s*=\s*["\'][^"\']+["\']',
            "Hardcoded credential variable assignment",
        ),
        (
            r'os\.environ\.get\s*\(.*?\)\s*or\s*["\'][^"\']+["\']',
            "Fallback to hardcoded default when env var missing",
        ),
        (r'["\']sk-[A-Za-z0-9]{32,}["\']', "OpenAI API key pattern"),
        (r'["\']ghp_[A-Za-z0-9]{36,}["\']', "GitHub personal access token pattern"),
        (r'["\']AKIA[A-Z0-9]{16,}["\']', "AWS access key pattern"),
    ]

    for pattern, msg in secret_patterns:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line_no = source[: match.start()].count("\n") + 1
            lines = source.split("\n")
            context = lines[line_no - 1] if line_no <= len(lines) else ""
            # Redact the actual secret in display
            redacted = re.sub(r'["\'][A-Za-z0-9_\-]{8,}["\']', '"***REDACTED***"', context)
            findings.append(
                {
                    "type": "hardcoded_secrets",
                    "severity": "Critical",
                    "line": line_no,
                    "code": redacted,
                    "message": f"Hardcoded secret: {msg}",
                    "fix": "Protocol: Externalized Configuration. Remove plain-text credentials, API keys, and tokens from the source code. Save them to a local '.env' file (which must be added to your '.gitignore') and load them dynamically using python-dotenv. Access them via environment variables: os.getenv('VARIABLE_NAME').",
                }
            )

    return findings
