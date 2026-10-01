from pathlib import Path

from sentinel.fixer.engine import apply_fix, backup_file


def test_backup_file(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.py"
    test_file.write_text("x = 1\n", encoding="utf-8")
    backup = backup_file(test_file)
    assert backup.exists()
    assert backup.name == "sample.py.bak"
    assert backup.read_text(encoding="utf-8") == "x = 1\n"


def test_apply_fix_crypto(tmp_path: Path) -> None:
    test_file = tmp_path / "crypto_vuln.py"
    test_file.write_text("import hashlib\nh = hashlib.md5(b'test')\n", encoding="utf-8")
    finding = {
        "id": "sast_insecure_crypto",
        "location": f"{test_file}:2",
        "line": 2,
    }
    success = apply_fix(finding, dry_run=False, base_dir=tmp_path)
    assert success is True
    content = test_file.read_text(encoding="utf-8")
    assert "hashlib.sha256(b'test')" in content
    assert (tmp_path / "crypto_vuln.py.bak").exists()


def test_apply_fix_path_traversal_blocked(tmp_path: Path) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    sensitive_file = outside_dir / "target.py"
    sensitive_file.write_text("API_KEY = 'secret123'\n", encoding="utf-8")

    # Attempt path traversal relative to project_dir
    finding = {
        "id": "sast_hardcoded_secrets",
        "location": str(outside_dir / "target.py") + ":1",
        "line": 1,
    }
    success = apply_fix(finding, dry_run=False, base_dir=project_dir)
    # Must fail safely and not modify file outside project
    assert success is False
    assert sensitive_file.read_text(encoding="utf-8") == "API_KEY = 'secret123'\n"
    assert not (outside_dir / "target.py.bak").exists()


def test_apply_fix_nonexistent_file(tmp_path: Path) -> None:
    finding = {
        "id": "sast_insecure_crypto",
        "location": str(tmp_path / "nonexistent.py:1"),
        "line": 1,
    }
    assert apply_fix(finding, base_dir=tmp_path) is False
