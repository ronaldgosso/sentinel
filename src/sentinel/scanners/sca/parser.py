import re
from pathlib import Path
from typing import List, Tuple, Any

import sys

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def parse_requirements_txt(content: str) -> List[Tuple[Any, Any, str]]:
    """Parse requirements.txt, return list of (package, version, ecosystem)."""
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
        deps.append((pkg, version, "PyPI"))
    return deps


def parse_pyproject_toml(content: str) -> List[Tuple[Any, Any, str]]:
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
        deps.append((pkg, version, "PyPI"))
    # optional dependencies
    for group, deps_list in data.get("project", {}).get("optional-dependencies", {}).items():
        for dep in deps_list:
            pkg = re.split(r"[;<>!=~]", dep)[0].strip()
            version = None
            match = re.search(r"([<>]=?|==|~=|!=)\s*([^;]+)", dep)
            if match:
                version = match.group(2).strip()
            deps.append((pkg, version, "PyPI"))
    return deps


def parse_poetry_lock(content: str) -> List[Tuple[Any, Any, str]]:
    """Parse poetry.lock (TOML) for packages and versions."""
    data = tomllib.loads(content)
    deps = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append((name, version, "PyPI"))
    return deps


def parse_uv_lock(content: str) -> List[Tuple[Any, Any, str]]:
    """Parse uv.lock (TOML) for packages and versions."""
    # uv.lock format similar to poetry but with different structure
    data = tomllib.loads(content)
    deps = []
    for pkg in data.get("packages", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append((name, version, "PyPI"))
    return deps


def parse_package_json(content: str) -> List[Tuple[Any, Any, str]]:
    """Parse package.json for dependencies and devDependencies."""
    import json

    data = json.loads(content)
    deps = []
    for key in ["dependencies", "devDependencies"]:
        for pkg, ver_range in data.get(key, {}).items():
            version = re.sub(r"^[~^>=<]*\s*", "", ver_range)
            deps.append((pkg, version, "npm"))
    return deps


def parse_package_lock_json(content: str) -> List[Tuple[Any, Any, str]]:
    """Parse package-lock.json for exact installed versions."""
    import json

    data = json.loads(content)
    deps = []
    packages = data.get("packages", {})
    for path, info in packages.items():
        if not path:
            continue
        name = path.replace("node_modules/", "")
        version = info.get("version")
        if name and version:
            deps.append((name, version, "npm"))
    if not deps:
        dependencies = data.get("dependencies", {})
        for name, info in dependencies.items():
            version = info.get("version")
            if name and version:
                deps.append((name, version, "npm"))
    return deps


def parse_go_mod(content: str) -> List[Tuple[Any, Any, str]]:
    """Parse go.mod for module dependencies."""
    deps = []
    pattern = r"^\s*([^\s]+)\s+(v[0-9]+\.[0-9]+\.[0-9]+[^\s]*)"
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        words = line.split()
        if not words:
            continue
        first_word = words[0]
        if first_word in ("module", "go", "(", ")"):
            # Skip module and go directives, plus open/close parentheses
            continue
        if first_word == "require":
            if len(words) > 1 and words[1] == "(":
                continue
            line = line[8:].strip()
        match = re.match(pattern, line)
        if match:
            name = match.group(1)
            version = match.group(2)
            deps.append((name, version, "Go"))
    return deps


def parse_dependency_file(filepath: Path) -> List[Tuple[Any, Any, str]]:
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
    elif filepath.name == "package.json":
        return parse_package_json(content)
    elif filepath.name == "package-lock.json":
        return parse_package_lock_json(content)
    elif filepath.name == "go.mod":
        return parse_go_mod(content)
    else:
        return []


def find_dependency_files(root_path: Path) -> List[Path]:
    """Find dependency files in the project root."""
    candidates = [
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "package.json",
        "package-lock.json",
        "go.mod",
    ]
    found = []
    for name in candidates:
        p = root_path / name
        if p.exists():
            found.append(p)
    return found
