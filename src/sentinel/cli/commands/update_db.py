import click
from rich.console import Console
from ...scanners.sca.vuln_db import get_vulnerabilities, init_db

console = Console()


@click.command()
@click.option("--force", is_flag=True, help="Force refresh of all cached data")
def update_db(force: bool) -> None:
    """Update the vulnerability database cache."""
    init_db()
    console.print("[yellow]Updating vulnerability cache...[/]")
    # For now, we just force refresh for a known package, or we can clear cache
    # We'll implement a simple refresh: re-query a sample
    if force:
        # Clear cache tables
        import sqlite3
        from pathlib import Path

        db_path = Path.home() / ".sentinel" / "vuln_cache.db"
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            conn.execute("DELETE FROM cache")
            conn.execute("DELETE FROM nvd_cache")
            conn.commit()
            conn.close()
            console.print("[green]Cache cleared. Will repopulate on next scan.[/]")
    else:
        # Just refresh a dummy package to test
        get_vulnerabilities("requests", "2.20.0", force_refresh=True)
        console.print("[green]Cache refreshed for sample package 'requests==2.20.0'.[/]")
