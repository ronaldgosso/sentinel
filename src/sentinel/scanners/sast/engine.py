import ast
from pathlib import Path
from typing import List, Optional, Dict, Any

from .rules import Rule, load_rules
from .detectors import (
    detect_sql_injection,
    detect_xss,
    detect_command_injection,
    detect_hardcoded_secrets,
    detect_insecure_crypto,
)

# Mapping of detector functions
DETECTOR_MAP = {
    "sql_injection": detect_sql_injection,
    "xss": detect_xss,
    "command_injection": detect_command_injection,
    "hardcoded_secrets": detect_hardcoded_secrets,
    "insecure_crypto": detect_insecure_crypto,
}


class Finding:
    def __init__(
        self,
        rule_id: str,
        severity: str,
        location: str,
        line: int,
        code_snippet: str,
        message: str,
        remediation: str,
        cwe: str,
        ai_confirmed: bool = False,
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.location = location
        self.line = line
        self.code_snippet = code_snippet
        self.message = message
        self.remediation = remediation
        self.cwe = cwe
        self.ai_confirmed = ai_confirmed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.rule_id,
            "severity": self.severity,
            "location": self.location,
            "line": self.line,
            "code": self.code_snippet,
            "message": self.message,
            "fix": self.remediation,
            "cwe": self.cwe,
            "ai_confirmed": self.ai_confirmed,
        }


class SASTScanner:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules = load_rules(rules_dir)
        self.findings: List[Finding] = []

    def scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single Python file using AST and detectors."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
        except Exception:
            return []  # skip unreadable files

        # Parse AST
        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            return []  # skip files with syntax errors

        findings = []

        # Run each detector
        for detector_name, detector_func in DETECTOR_MAP.items():
            detector_findings = detector_func(tree, source, str(filepath))
            for finding_data in detector_findings:
                # Map severity from detector
                severity = finding_data.get("severity", "Medium")
                # Try to find matching rule for remediation
                rule = self._find_matching_rule(detector_name, finding_data)
                finding = Finding(
                    rule_id=rule.id if rule else detector_name,
                    severity=severity,
                    location=str(filepath),
                    line=finding_data.get("line", 0),
                    code_snippet=finding_data.get("code", ""),
                    message=finding_data.get("message", detector_name),
                    remediation=rule.remediation
                    if rule
                    else finding_data.get("fix", "Review code."),
                    cwe=rule.cwe if rule else "N/A",
                    ai_confirmed=False,  # will be set by Phase 4
                )
                findings.append(finding)

        return findings

    def _find_matching_rule(
        self, detector_name: str, finding_data: Dict[str, Any]
    ) -> Optional[Rule]:
        """Find a rule that matches this detector and context."""
        for rule in self.rules:
            if detector_name in rule.id:
                return rule
        return None

    def scan_directory(self, root_path: str) -> List[Finding]:
        """Scan all Python files in a directory."""
        from ...utils.file_walker import walk_python_files

        all_findings = []
        files = walk_python_files(root_path)

        for filepath in files:
            all_findings.extend(self.scan_file(filepath))

        self.findings = all_findings
        return all_findings
