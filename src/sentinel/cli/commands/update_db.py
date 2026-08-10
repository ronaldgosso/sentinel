import click
from rich.console import Console

from ...scanners.sca.vuln_db import get_db_connection, get_vulnerabilities, init_db

console = Console()


@click.command()
@click.option("--force", is_flag=True, help="Force refresh of all cached data")
def update_db(force: bool) -> None:
    """Update the vulnerability database cache."""
    init_db()
    console.print("[yellow]Updating vulnerability cache...[/]")
    if force:
        # Clear cache tables using the project's DB connection helper
        with get_db_connection() as conn:
            conn.execute("DELETE FROM cache")
            conn.execute("DELETE FROM nvd_cache")
            conn.commit()
        console.print("[green]Cache cleared. Will repopulate on next scan.[/]")
    else:
        # Just refresh a dummy package to test
        get_vulnerabilities("requests", "2.20.0", force_refresh=True)
        console.print("[green]Cache refreshed for sample package 'requests==2.20.0'.[/]")
