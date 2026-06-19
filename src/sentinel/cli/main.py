import click
from .commands.scan import scan
from .commands.init import init
from .commands.update_db import update_db


@click.group()
def cli() -> None:
    """Sentinel – AI-Powered Security Hardening."""
    pass


cli.add_command(scan)
cli.add_command(init)
cli.add_command(update_db)

if __name__ == "__main__":
    cli()
