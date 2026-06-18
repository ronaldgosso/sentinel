import yaml
from pathlib import Path
from typing import Dict, Any

CONFIG_PATHS = [
    Path.cwd() / "sentinel.yml",
    Path.cwd() / ".sentinel.yml",
    Path.home() / ".sentinel/config.yml",
]


def load_config() -> Dict[str, Any]:
    """Load configuration from sentinel.yml, with defaults."""
    config = {
        "exclude_patterns": [".venv", "venv", "env", "__pycache__", ".git", "tests"],
        "severity_threshold": "medium",
        "ai_enabled": True,
        "max_workers": 4,
        "rules_dir": str(Path(__file__).parent.parent / "scanners" / "sast" / "rules"),
    }
    for path in CONFIG_PATHS:
        if path.exists():
            with open(path) as f:
                user_config = yaml.safe_load(f) or {}
                config.update(user_config)
            break
    return config
