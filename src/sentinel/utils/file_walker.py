import os
from pathlib import Path
from typing import List, Optional


def walk_source_files(root_path: str, ignore_patterns: Optional[List[str]] = None) -> List[Path]:
    """Walk directory and return all source files, respecting .sentinelignore."""
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
    source_files = []
    root = Path(root_path).resolve()
    
    # Supported file extensions for SAST scanning
    extensions = (".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css")

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip ignored directories
        dirnames[:] = [d for d in dirnames if d not in ignore_patterns and not d.startswith(".")]
        for fname in filenames:
            if fname.endswith(extensions) and not fname.startswith("test_"):
                full_path = Path(dirpath) / fname
                source_files.append(full_path)
    return source_files
