import re
from pathlib import Path
from typing import Dict, Any
import shutil


def backup_file(filepath: Path) -> Path:
    """Create a backup of the file before fixing."""
    backup = filepath.with_suffix(filepath.suffix + ".bak")
    shutil.copy2(filepath, backup)
    return backup


def apply_fix(finding: Dict[str, Any], dry_run: bool = False) -> bool:
    """Apply fix for a single finding. Returns True if successful."""
    location = finding.get("location", "")
    if not location:
        return False

    # location could be "file:line" or just file
    parts = location.split(":")
    if len(parts) >= 2 and parts[-1].isdigit():
        filepath = Path(":".join(parts[:-1]))
        line_no = int(parts[-1])
    else:
        filepath = Path(location)
        line_no = finding.get("line", 0)

    if not filepath.exists():
        return False

    # Read file content
    with open(filepath, "r") as f:
        lines = f.readlines()

    if line_no < 1 or line_no > len(lines):
        return False

    # Determine fix type from finding id
    finding_id = finding.get("id", "")
    modified = False
    original_line = lines[line_no - 1]
    new_line = original_line

    if "insecure_crypto" in finding_id:
        # Replace md5/sha1 with sha256
        new_line = re.sub(r"hashlib\.md5", "hashlib.sha256", original_line)
        new_line = re.sub(r"hashlib\.sha1", "hashlib.sha256", new_line)
        if new_line != original_line:
            modified = True
    elif "hardcoded_secrets" in finding_id:
        # Replace hardcoded secret with os.getenv
        # We'll try to replace the value with os.getenv("VAR_NAME")
        match = re.search(r'([A-Z_]+)\s*=\s*["\'][^"\']+["\']', original_line)
        if match:
            var_name = match.group(1)
            new_line = re.sub(r'["\'][^"\']+["\']', f'os.getenv("{var_name}")', original_line)
            # Add import os if not present
            if "import os" not in "".join(lines) and "from os import" not in "".join(lines):
                # Insert import at top
                lines.insert(0, "import os\n")
                line_no += 1  # adjust for inserted line
            modified = True
    elif "sql_injection" in finding_id:
        # Suggest parameterization; we can comment the line and add a comment
        # We'll add a comment with the fix suggestion
        new_line = "# FIXME: " + original_line + "# Parameterize this query\n"
        modified = True
    elif "xss" in finding_id:
        # Remove |safe or mark_safe
        new_line = re.sub(r"\|\s*safe", "", original_line)
        new_line = re.sub(r"mark_safe\s*\(", "", new_line)
        if new_line != original_line:
            modified = True
    elif "command_injection" in finding_id:
        # Comment out shell=True, add suggestion
        new_line = re.sub(
            r"shell\s*=\s*True", "shell=False  # Consider passing arguments as list", original_line
        )
        if new_line != original_line:
            modified = True

    if not modified:
        return False

    if not dry_run:
        # Backup file
        backup_file(filepath)
        # Apply change
        lines[line_no - 1] = new_line
        with open(filepath, "w") as f:
            f.writelines(lines)

    return True
