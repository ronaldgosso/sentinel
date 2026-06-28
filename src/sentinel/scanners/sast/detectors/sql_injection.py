import ast
import re
from typing import List, Dict, Any, Optional


def detect_sql_injection(tree: Optional[ast.AST], source: str, filename: str) -> List[Dict[str, Any]]:
    """Detect SQL injection vulnerabilities (string formatting in SQL queries)."""
    findings = []

    # Patterns for dangerous SQL construction
    dangerous_patterns = [
        (r'execute\s*\(\s*["\']SELECT.*?["\']\s*%', "String formatting in SQL execute()"),
        (r'execute\s*\(\s*["\']SELECT.*?["\']\.format', ".format() in SQL execute()"),
        (r'execute\s*\(\s*f["\']SELECT.*?["\']', "f-string in SQL execute()"),
        (r'raw\s*\(\s*["\']SELECT.*?["\']\s*%', "String formatting in raw() (Django)"),
        (r'raw\s*\(\s*f["\']SELECT.*?["\']', "f-string in raw() (Django)"),
        (r'cursor\.execute\s*\(\s*["\']SELECT.*?["\']\s*%', "cursor.execute with %"),
        (r'cursor\.execute\s*\(\s*["\']SELECT.*?["\']\.format', "cursor.execute with .format"),
        (r'cursor\.execute\s*\(\s*f["\']SELECT.*?["\']', "cursor.execute with f-string"),
    ]

    # Also check for parameterised query absence (we flag risky patterns)
    for pattern, msg in dangerous_patterns:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line_no = source[: match.start()].count("\n") + 1
            # Get context lines
            lines = source.split("\n")
            context = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(
                {
                    "type": "sql_injection",
                    "severity": "Critical",
                    "line": line_no,
                    "code": context.strip(),
                    "message": f"Potential SQL Injection: {msg}",
                    "fix": "Protocol: Parameterized Queries. Replace string concatenation or formatting inside SQL executions with placeholders and pass query parameters as a tuple. Example: Change cursor.execute(f'SELECT * FROM users WHERE username = \"{user}\"') to cursor.execute('SELECT * FROM users WHERE username = ?', (user,)).",
                }
            )

    return findings
