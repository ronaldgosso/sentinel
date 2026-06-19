import click
from pathlib import Path
from rich.console import Console

console = Console()


@click.command()
def init() -> None:
    """Create a default .sentinel.yml configuration file."""
    config_path = Path.cwd() / ".sentinel.yml"
    if config_path.exists():
        console.print("[yellow].sentinel.yml already exists. Overwrite? (y/n)[/]")
        if not click.confirm(""):
            return
    template = """# Sentinel Configuration
# See https://sentinel.dev/docs for all options.

# Directories to exclude from scanning
exclude_patterns:
  - .venv
  - venv
  - env
  - __pycache__
  - .git
  - node_modules
  - tests
  - test_*

# Minimum severity to report (critical, high, medium, low)
severity_threshold: medium

# Enable AI analysis by default
ai_enabled: true

# AI backend: cloud (default) or local
ai_backend: cloud

# Max workers for parallel scanning
max_workers: 4

# Custom rule directory (relative to project root)
rules_dir: rules
"""
    config_path.write_text(template)
    console.print(f"[green]Created .sentinel.yml at {config_path}[/]")
