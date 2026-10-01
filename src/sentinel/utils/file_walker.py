import fnmatch
import os
from pathlib import Path


def _matches_any_pattern(name: str, patterns: list[str], rel_path: str | None = None) -> bool:
    """Check if name or relative path matches any of the given glob patterns."""
    for p in patterns:
        clean_p = p.strip("/")
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(name, clean_p):
            return True
        if rel_path and (fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(rel_path, clean_p)):
            return True
    return False


def walk_source_files(root_path: str, ignore_patterns: list[str] | None = None) -> list[Path]:
    """Walk directory and return all source files, respecting .sentinelignore."""
    patterns = list(
        ignore_patterns
        if ignore_patterns is not None
        else [
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
    )
    root = Path(root_path).resolve()
    sentinelignore = root / ".sentinelignore"
    if sentinelignore.is_file():
        try:
            with open(sentinelignore, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        patterns.append(stripped)
        except OSError:
            pass

    source_files = []
    # Supported file extensions for SAST scanning
    extensions = (".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".css")

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dirpath = Path(dirpath).relative_to(root)
        # Skip ignored directories (use fnmatch for glob patterns)
        dirnames[:] = [
            d
            for d in dirnames
            if not _matches_any_pattern(
                d, patterns, str(rel_dirpath / d).replace("\\", "/")
            )
            and not d.startswith(".")
        ]
        for fname in filenames:
            rel_file = str(rel_dirpath / fname).replace("\\", "/")
            if fname.endswith(extensions) and not _matches_any_pattern(
                fname, patterns, rel_file
            ):
                full_path = Path(dirpath) / fname
                source_files.append(full_path)
    return source_files
