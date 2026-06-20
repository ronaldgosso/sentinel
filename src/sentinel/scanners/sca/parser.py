import re
from pathlib import Path
from typing import List, Tuple, Any

try:
    import tomli as tomllib  # for Python < 3.11
except ImportError:
    import tomllib  # Python 3.11+


def parse_requirements_txt(content: str) -> List[Tuple[Any, Any]]:
    """Parse requirements.txt, return list of (package, version)."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # handle -r, -e, etc. skip for now
        if line.startswith("-") or line.startswith("#"):
            continue
        # remove extras and hashes
        pkg = re.split(r"[;<>!=~]", line)[0].strip()
        if not pkg:
            continue
        # extract version if present
        version = None
        match = re.search(r"([<>]=?|==|~=|!=)\s*([^;]+)", line)
        if match:
            version = match.group(2).strip()
        deps.append((pkg, version))
    return deps


def parse_pyproject_toml(content: str) -> List[Tuple[Any, Any]]:
    """Parse pyproject.toml for dependencies and dev-dependencies."""
    data = tomllib.loads(content)
    deps = []
    # project.dependencies
    for dep in data.get("project", {}).get("dependencies", []):
        # similar to requirements parsing
        pkg = re.split(r"[;<>!=~]", dep)[0].strip()
        version = None
        match = re.search(r"([<>]=?|==|~=|!=)\s*([^;]+)", dep)
        if match:
            version = match.group(2).strip()
        deps.append((pkg, version))
    # optional dependencies
    for group, deps_list in data.get("project", {}).get("optional-dependencies", {}).items():
        for dep in deps_list:
            pkg = re.split(r"[;<>!=~]", dep)[0].strip()
            version = None
            match = re.search(r"([<>]=?|==|~=|!=)\s*([^;]+)", dep)
            if match:
                version = match.group(2).strip()
            deps.append((pkg, version))
    return deps


def parse_poetry_lock(content: str) -> List[Tuple[Any, Any]]:
    """Parse poetry.lock (TOML) for packages and versions."""
    data = tomllib.loads(content)
    deps = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append((name, version))
    return deps


def parse_uv_lock(content: str) -> List[Tuple[Any, Any]]:
    """Parse uv.lock (TOML) for packages and versions."""
    # uv.lock format similar to poetry but with different structure
    data = tomllib.loads(content)
    deps = []
    for pkg in data.get("packages", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append((name, version))
    return deps


def parse_dependency_file(filepath: Path) -> List[Tuple[Any, Any]]:
    """Detect file type and parse accordingly."""
    content = filepath.read_text(encoding="utf-8")
    if filepath.name == "requirements.txt":
        return parse_requirements_txt(content)
    elif filepath.name == "pyproject.toml":
        return parse_pyproject_toml(content)
    elif filepath.name == "poetry.lock":
        return parse_poetry_lock(content)
    elif filepath.name == "uv.lock":
        return parse_uv_lock(content)
    else:
        return []


def find_dependency_files(root_path: Path) -> List[Path]:
    """Find dependency files in the project root."""
    candidates = ["requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock"]
    found = []
    for name in candidates:
        p = root_path / name
        if p.exists():
            found.append(p)
    return found
