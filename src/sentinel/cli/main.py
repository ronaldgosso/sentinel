import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box
import time

console = Console()

# ----- mock data for the demo -----
MOCK_FINDINGS = [
    {
        "id": 1,
        "severity": "Critical",
        "type": "SQL Injection",
        "location": "auth.py:42",
        "code": "query = f\"SELECT * FROM users WHERE email = '{email}'\"",
        "attack": "Attacker supplies email = \"' OR '1'='1\" to bypass login.",
        "fix": 'Use parameterised query:\nquery = "SELECT * FROM users WHERE email = ?"\ncursor.execute(query, (email,))',
        "ai_confirmed": True,
    },
    {
        "id": 2,
        "severity": "Critical",
        "type": "Hardcoded Secret",
        "location": "config.py:15",
        "code": 'API_KEY = "sk-1234567890abcdef"',
        "attack": "Secret exposed in source code; anyone with repo access can steal it.",
        "fix": 'Use environment variable:\nAPI_KEY = os.getenv("API_KEY")',
        "ai_confirmed": True,
    },
    {
        "id": 3,
        "severity": "High",
        "type": "XSS (Reflected)",
        "location": "templates/index.html:22",
        "code": "<div>{{ user_input | safe }}</div>",
        "attack": "Malicious JavaScript can be injected via URL parameters.",
        "fix": "Remove | safe filter and autoescape:\n<div>{{ user_input }}</div>",
        "ai_confirmed": False,
    },
    {
        "id": 4,
        "severity": "Medium",
        "type": "Insecure Crypto",
        "location": "crypto_utils.py:8",
        "code": "hash = hashlib.md5(password.encode()).hexdigest()",
        "attack": "MD5 is collision‑prone; attackers can generate same hash.",
        "fix": "Use hashlib.sha256 or bcrypt:\nhash = hashlib.sha256(password.encode()).hexdigest()",
        "ai_confirmed": True,
    },
    {
        "id": 5,
        "severity": "Low",
        "type": "Missing Security Header",
        "location": "app.py:120",
        "code": 'response = make_response("OK")',
        "attack": "Missing CSP allows XSS in older browsers.",
        "fix": 'response.headers["Content-Security-Policy"] = "default-src \'self\'"',
        "ai_confirmed": False,
    },
]


def run_scan() -> None:
    """Simulate a scan with progress bars."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        t1 = progress.add_task("[cyan]SAST: parsing AST...", total=None)
        time.sleep(1.2)
        progress.update(t1, completed=True)

        t2 = progress.add_task("[green]SCA: checking dependencies...", total=None)
        time.sleep(0.8)
        progress.update(t2, completed=True)

        t3 = progress.add_task("[magenta]AI: Mistral analysing findings...", total=None)
        time.sleep(1.5)
        progress.update(t3, completed=True)

    # Summary panel
    counts = {"Critical": 2, "High": 1, "Medium": 1, "Low": 1}
    summary = Panel(
        f"[bold red]🔴 Critical: {counts['Critical']}[/]   "
        f"[bold orange1]🟠 High: {counts['High']}[/]   "
        f"[bold yellow]🟡 Medium: {counts['Medium']}[/]   "
        f"[bold green]🟢 Low: {counts['Low']}[/]",
        title="Vulnerability Summary",
        border_style="bright_blue",
    )
    console.print(summary)

    # Main findings table
    table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=12)
    table.add_column("Type", width=20)
    table.add_column("Location", width=20)
    table.add_column("AI ✅", width=6)

    for f in MOCK_FINDINGS:
        sev_color = (
            "red"
            if f["severity"] == "Critical"
            else "orange1"
            if f["severity"] == "High"
            else "yellow"
            if f["severity"] == "Medium"
            else "green"
        )
        ai_mark = "✅" if f["ai_confirmed"] else "❌"
        table.add_row(
            str(f["id"]),
            f"[{sev_color}]{f['severity']}[/]",
            f["type"],
            f["location"],
            ai_mark,
        )
    console.print(table)


def show_detail(finding_id: int) -> None:
    """Drill‑down view for a specific finding."""
    f = next((x for x in MOCK_FINDINGS if x["id"] == finding_id), None)
    if not f:
        console.print("[red]Finding not found.[/]")
        return

    console.rule(f"[bold]🔎 Finding #{f['id']} – {f['type']}[/]")
    console.print(f"[bold]Severity:[/] [red]{f['severity']}[/]")
    console.print(f"[bold]Location:[/] {f['location']}")
    console.print(f"[bold]Code snippet:[/]\n[italic cyan]{f['code']}[/]")
    console.print(f"\n[bold yellow]Attack scenario:[/]\n{f['attack']}")
    console.print(f"\n[bold green]Hardening suggestion (AI‑generated):[/]\n{f['fix']}")

    if Confirm.ask("Apply this fix automatically?", default=False):
        # In a real tool, we'd patch the file – here we just fake it.
        console.print("[bold green]✅ Fix applied to file. Please review the change.[/]")
    else:
        console.print("[dim]Skipped.[/]")
    input("\nPress Enter to return to the dashboard...")


@click.command()  # type: ignore[misc]
@click.argument("path", default=".", type=click.Path(exists=True))  # type: ignore[misc]
@click.option("--ai/--no-ai", default=True, help="Enable/disable AI analysis")  # type: ignore[misc]
@click.option("--ci", is_flag=True, help="CI mode – non‑interactive, exit with code")  # type: ignore[misc]
def cli(path: str, ai: bool, ci: bool) -> None:
    """Sentinel – AI‑Powered Security Hardening."""
    console.print(
        Panel.fit(
            "[bold blue]🔍 Sentinel v0.1.0[/] – AI‑Powered Security Hardening", border_style="blue"
        )
    )
    console.print(f"Scanning [cyan]{path}[/] ...")

    if ci:
        console.print("[yellow]CI mode – running non‑interactive scan.[/]")
        # Simulate scan and exit with code based on critical count
        console.print("✅ Scan complete. Found 2 Critical issues.")
        raise SystemExit(1)  # Fail CI if critical found

    # Interactive flow
    run_scan()

    while True:
        choice = Prompt.ask("Enter #[bold]#[/] to see details, or [bold]q[/] to quit", default="q")
        if choice.lower() == "q":
            console.print("[dim]Generating optional report...[/]")
            export = Confirm.ask("Save a report? (JSON/SARIF/HTML)", default=False)
            if export:
                console.print("[green]Report saved as sentinel-report.json[/] (mock)")
            console.print("[bold] Goodbye! Stay secure.[/]")
            break
        try:
            fid = int(choice)
            show_detail(fid)
        except ValueError:
            console.print("[red]Invalid input. Enter a number or 'q'.[/]")
