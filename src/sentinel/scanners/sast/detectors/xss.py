import ast
import re
from typing import List, Dict, Any


def detect_xss(tree: ast.AST, source: str, filename: str) -> List[Dict[str, Any]]:
    """Detect XSS vulnerabilities (unsafe rendering in templates)."""
    findings = []

    # Patterns for unsafe output in templates
    xss_patterns = [
        (r"{{.*?\|safe}}", "Use of '|safe' filter in Jinja template (XSS risk)"),
        (r"{% autoescape false %}", "Autoescape disabled in Jinja template"),
        (r"{{.*?\|raw}}", "Use of '|raw' filter in Twig/Django (XSS risk)"),
        (r"mark_safe\s*\(", "mark_safe() used in Django (XSS risk if input unsanitised)"),
        (r"HTML\s*\(.*?\)", "HTML() constructor in Flask/JavaScript context (XSS risk)"),
        (r"innerHTML\s*=", "innerHTML assignment in JavaScript (XSS risk)"),
        (r"document\.write\s*\(", "document.write() in JavaScript (XSS risk)"),
        (r"\.html\s*\(", "jQuery .html() with unsanitised data"),
    ]

    for pattern, msg in xss_patterns:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line_no = source[: match.start()].count("\n") + 1
            lines = source.split("\n")
            context = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(
                {
                    "type": "xss",
                    "severity": "High",
                    "line": line_no,
                    "code": context.strip(),
                    "message": f"Potential XSS: {msg}",
                    "fix": "Protocol: Output Encoding & Context-Aware Escaping. Remove raw rendering filters like '|safe' or 'mark_safe()' for user-controlled inputs. Always HTML-escape variables using template engine auto-escaping (e.g. Jinja/Django default) or escape values explicitly using python's 'html.escape()' module.",
                }
            )

    return findings
