import os
from pathlib import Path
from typing import List, Optional


def walk_python_files(root_path: str, ignore_patterns: Optional[List[str]] = None) -> List[Path]:
    """Walk directory and return all .py files, respecting .sentinelignore."""
    ignore_patterns = ignore_patterns or [
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "*.pyc",
        ".git",
        "node_modules",
        "tests",
        "test_*",
    ]
    python_files = []
    root = Path(root_path).resolve()

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip ignored directories
        dirnames[:] = [d for d in dirnames if d not in ignore_patterns and not d.startswith(".")]
        for fname in filenames:
            if fname.endswith(".py") and not fname.startswith("test_"):
                full_path = Path(dirpath) / fname
                python_files.append(full_path)
    return python_files
