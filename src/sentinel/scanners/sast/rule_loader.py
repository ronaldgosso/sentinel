import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional


class Rule:
    def __init__(self, data: Dict[str, Any]):
        self.id = data["id"]
        self.name = data["name"]
        self.cwe = data.get("cwe", "N/A")
        self.severity = data.get("severity", "Medium")  # Critical, High, Medium, Low
        self.description = data.get("description", "")
        self.remediation = data.get("remediation", "")
        self.pattern_type = data.get("pattern_type", "ast")  # "ast" or "regex"
        self.pattern = data.get("pattern")  # AST matcher or regex
        self.file_patterns = data.get("file_patterns", ["*.py"])
        self.exclude = data.get("exclude", [])
        self.message_template = data.get("message", "{vuln_type} detected at {location}")

    def matches_file(self, filepath: Path) -> bool:
        # Simple glob matching for now
        import fnmatch

        for pattern in self.file_patterns:
            if fnmatch.fnmatch(filepath.name, pattern):
                return True
        return False


def load_rules(rules_dir: Optional[str] = None) -> List[Rule]:
    """Load all YAML rules from the rules directory."""
    if rules_dir is None:
        rules_dir = str(Path(__file__).parent / "rules")
    rules: List[Rule] = []
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        return rules  # empty if no rules yet

    for yaml_file in rules_path.glob("*.yaml"):
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
            if isinstance(data, list):
                for item in data:
                    rules.append(Rule(item))
            elif isinstance(data, dict):
                rules.append(Rule(data))
    return rules
