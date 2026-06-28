import ast
import re
from typing import List, Dict, Any, Optional


def detect_frontend_vulnerabilities(
    tree: Optional[ast.AST], source: str, filename: str
) -> List[Dict[str, Any]]:
    """Detect frontend specific vulnerabilities (e.g. dangerouslySetInnerHTML, reverse tabnabbing)."""
    findings = []

    frontend_patterns = [
        (r"dangerouslySetInnerHTML", "Usage of dangerouslySetInnerHTML in React/JSX (XSS risk)"),
        (r"v-html", "Usage of v-html in Vue (XSS risk)"),
        (r"ng-bind-html", "Usage of ng-bind-html in Angular (XSS risk)"),
        (r"bypassSecurityTrustHtml", "Usage of bypassSecurityTrustHtml in Angular (XSS risk)"),
        (
            r'target\s*=\s*["\']_blank["\'](?!.*rel\s*=\s*["\'].*noopener.*["\'])',
            'target="_blank" without rel="noopener noreferrer" (Reverse Tabnabbing risk)',
        ),
        (r"href\s*=\s*[\"']javascript:", "javascript: URI used in href attribute (XSS risk)"),
        (r"eval\s*\(", "eval() function in JavaScript (Command/Code Injection risk)"),
        (
            r"setTimeout\s*\(\s*['\"`].*?['\"`]\s*,",
            "setTimeout() with a string argument (eval-like Code Injection risk)",
        ),
        (
            r"setInterval\s*\(\s*['\"`].*?['\"`]\s*,",
            "setInterval() with a string argument (eval-like Code Injection risk)",
        ),
        (r"\.innerHTML\s*=", "innerHTML assignment (XSS risk)"),
        (r"\.outerHTML\s*=", "outerHTML assignment (XSS risk)"),
        (r"document\.write\s*\(", "document.write() (XSS risk)"),
        (r"document\.writeln\s*\(", "document.writeln() (XSS risk)"),
        (
            r"<script(?!.*?src=)(?!.*?nonce=).*?>",
            "Inline <script> tag without src or nonce attributes (CSP bypass risk)",
        ),
        (
            r"<iframe(?!.*?sandbox=).*?>",
            "iframe tag without sandbox attribute (Sandboxing bypass risk)",
        ),
        (r"\son\w+\s*=\s*[\"']", "Inline event handler (XSS risk)"),
    ]

    for pattern, msg in frontend_patterns:
        # Check against source as string, ignoring case
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line_no = source[: match.start()].count("\n") + 1
            lines = source.split("\n")
            context = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(
                {
                    "type": "frontend_vuln",
                    "severity": "High",
                    "line": line_no,
                    "code": context.strip(),
                    "message": f"Frontend Vulnerability: {msg}",
                    "fix": "Protocol: Secure Frontend Practices. Avoid rendering raw HTML (e.g., dangerouslySetInnerHTML, v-html). If necessary, sanitize input using DOMPurify. Avoid 'eval' or string-based timeouts. Use rel='noopener noreferrer' when using target='_blank'. Do not use javascript: URIs.",
                }
            )

    return findings
