from pathlib import Path

from sentinel.utils.file_walker import walk_source_files


def test_walk_source_files_respects_sentinelignore(tmp_path: Path) -> None:
    # Create directory structure
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    valid_file = src_dir / "app.py"
    valid_file.write_text("print('hello')\n", encoding="utf-8")

    ignored_dir = tmp_path / "ignored_folder"
    ignored_dir.mkdir()
    ignored_file_in_dir = ignored_dir / "secret.py"
    ignored_file_in_dir.write_text("token = '123'\n", encoding="utf-8")

    ignored_individual = src_dir / "mock_data.py"
    ignored_individual.write_text("data = []\n", encoding="utf-8")

    # Write .sentinelignore
    ignore_file = tmp_path / ".sentinelignore"
    ignore_file.write_text(
        "# Comments should be ignored\n"
        "ignored_folder\n"
        "mock_data.py\n",
        encoding="utf-8",
    )

    files = walk_source_files(str(tmp_path))
    file_names = [f.name for f in files]

    assert "app.py" in file_names
    assert "mock_data.py" not in file_names
    assert "secret.py" not in file_names
