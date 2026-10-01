import contextlib
import sys

import click

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        with contextlib.suppress(Exception):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        with contextlib.suppress(Exception):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from .commands.init import init
from .commands.scan import scan
from .commands.update_db import update_db


@click.group()
def cli() -> None:
    """Sentinel – AI-Powered Security Hardening."""


cli.add_command(scan)
cli.add_command(init)
cli.add_command(update_db)

if __name__ == "__main__":
    cli()
