import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box
import time
from pathlib import Path

from ..scanners.sast.engine import SASTScanner
from ..scanners.sca.engine import SCAScanner
from ..scanners.dast.engine import DASTScanner  # new import
from typing import Any, Optional

console = Console()


def combine_findings(sast_findings: Any, sca_findings: Any, dast_findings: Any) -> Any:
    """Combine SAST, SCA, and DAST findings into one list."""
    combined = []
    for f in sca_findings:
        combined.append(f.to_dict())
    for f in sast_findings:
        combined.append(f.to_dict())
    for f in dast_findings:
        combined.append(f.to_dict())
    return combined


def run_scan(
    path: str,
    ai_enabled: bool,
    skip_sast: bool,
    skip_sca: bool,
    dast_url: Optional[str] = None,
    progress: bool = True,
) -> Any:
    """Orchestrate scanning and return combined findings."""
    combined = []
    if not skip_sast:
        scanner_sast = SASTScanner()
        sast_findings = scanner_sast.scan_directory(path)
        combined.extend([f.to_dict() for f in sast_findings])
    if not skip_sca:
        scanner_sca = SCAScanner()
        sca_findings = scanner_sca.scan_directory(path)
        combined.extend([f.to_dict() for f in sca_findings])
    if dast_url:
        scanner_dast = DASTScanner(dast_url)
        dast_findings = scanner_dast.scan()
        combined.extend([f.to_dict() for f in dast_findings])
    return combined


@click.command()  # type: ignore[misc]
@click.argument("path", default=".", type=click.Path(exists=True))  # type: ignore[misc]
@click.option("--ai/--no-ai", default=True, help="Enable/disable AI analysis (Phase 4)")  # type: ignore[misc]
@click.option("--ci", is_flag=True, help="CI mode – non-interactive, exit with code")  # type: ignore[misc]
@click.option("--skip-sast", is_flag=True, help="Skip SAST scanning")  # type: ignore[misc]
@click.option("--skip-sca", is_flag=True, help="Skip SCA scanning")  # type: ignore[misc]
@click.option(
    "--dast", help="Enable DAST scanning against the given target URL (e.g., http://localhost:8000)"
)  # type: ignore[misc]
def cli(
    path: str, ai: bool, ci: bool, skip_sast: bool, skip_sca: bool, dast: Optional[str]
) -> None:
    """Sentinel – AI-Powered Security Hardening."""
    console.print(
        Panel.fit(
            "[bold blue]🔍 Sentinel v0.1.0[/] – AI‑Powered Security Hardening", border_style="blue"
        )
    )

    if dast:
        console.print(f"DAST enabled: scanning [cyan]{dast}[/]")
    else:
        console.print(f"Scanning [cyan]{path}[/] ...")

    if ci:
        console.print("[yellow]CI mode – running non-interactive scan.[/]")
        combined = run_scan(
            path, ai_enabled=ai, skip_sast=skip_sast, skip_sca=skip_sca, dast_url=dast
        )
        critical_high = [f for f in combined if f["severity"] in ("Critical", "High")]
        console.print(f"✅ Scan complete. Found {len(critical_high)} Critical/High issues.")
        if critical_high:
            raise SystemExit(1)
        else:
            raise SystemExit(0)

    # Interactive flow – run scan with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        tasks = []
        if not skip_sast:
            tasks.append(progress.add_task("[cyan]SAST: scanning code...", total=None))
        if not skip_sca:
            tasks.append(progress.add_task("[green]SCA: checking dependencies...", total=None))
        if dast:
            tasks.append(progress.add_task("[red]DAST: testing web application...", total=None))

        # Actually run the scan
        combined = run_scan(
            path, ai_enabled=ai, skip_sast=skip_sast, skip_sca=skip_sca, dast_url=dast
        )

        for task in tasks:
            progress.update(task, completed=True)

        if ai:
            t_ai = progress.add_task(
                "[magenta]AI: Mistral analysing findings... (Phase 4)", total=None
            )
            time.sleep(0.5)
            progress.update(t_ai, completed=True)

    # Show results (same as before, now with DAST findings)
    if not combined:
        console.print("[bold green]✅ No security issues found![/]")
        return

    # Count by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in combined:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1

    summary = Panel(
        f"[bold red]🔴 Critical: {severity_counts['Critical']}[/]   "
        f"[bold orange1]🟠 High: {severity_counts['High']}[/]   "
        f"[bold yellow]🟡 Medium: {severity_counts['Medium']}[/]   "
        f"[bold green]🟢 Low: {severity_counts['Low']}[/]",
        title=f"Vulnerability Summary ({len(combined)} total)",
        border_style="bright_blue",
    )
    console.print(summary)

    # Main findings table
    table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=12)
    table.add_column("Type", width=20)
    table.add_column("Location", width=25)
    table.add_column("Line", width=6)
    table.add_column("AI ✅", width=6)

    for idx, f in enumerate(combined, 1):
        sev_color = (
            "red"
            if f["severity"] == "Critical"
            else "orange1"
            if f["severity"] == "High"
            else "yellow"
            if f["severity"] == "Medium"
            else "green"
        )
        # Determine type from id
        if "sca" in f["id"]:
            type_display = "SCA Vulnerability"
        elif "dast" in f["id"]:
            type_display = "DAST Vulnerability"
        else:
            type_display = f["id"].replace("_", " ").title()
        ai_mark = "✅" if f.get("ai_confirmed", False) else "❌"
        loc = f["location"]
        if ":" in loc:
            parts = loc.split(":")
            if len(parts) >= 2 and parts[-1].isdigit():
                loc_file = Path(parts[0]).name
                loc_line = parts[-1]
            else:
                loc_file = loc[:20]
                loc_line = str(f.get("line", ""))
        else:
            loc_file = loc[:20]
            loc_line = str(f.get("line", ""))
        table.add_row(
            str(idx),
            f"[{sev_color}]{f['severity']}[/]",
            type_display,
            loc_file[:20],
            loc_line,
            ai_mark,
        )
    console.print(table)

    # Interactive drill-down
    while True:
        choice = Prompt.ask("Enter #[bold]#[/] to see details, or [bold]q[/] to quit", default="q")
        if choice.lower() == "q":
            export = Confirm.ask("Save a report? (JSON/SARIF/HTML)", default=False)
            if export:
                console.print("[green]Report saved as sentinel-report.json[/] (mock)")
            console.print("[bold]👋 Goodbye! Stay secure.[/]")
            break
        try:
            fidx = int(choice)
            if 1 <= fidx <= len(combined):
                f = combined[fidx - 1]
                sev_color = (
                    "red"
                    if f["severity"] == "Critical"
                    else "orange1"
                    if f["severity"] == "High"
                    else "yellow"
                    if f["severity"] == "Medium"
                    else "green"
                )
                console.rule(f"[bold]🔎 Finding #{fidx} – {f['id'].replace('_', ' ').title()}[/]")
                console.print(f"[bold]Severity:[/] [{sev_color}]{f['severity']}[/]")
                console.print(f"[bold]Location:[/] {f['location']}")
                if f.get("line"):
                    console.print(f"[bold]Line:[/] {f['line']}")
                console.print(f"[bold]CWE:[/] {f.get('cwe', 'N/A')}")
                console.print(f"[bold]Code snippet:[/]\n[italic cyan]{f.get('code', 'N/A')}[/]")
                console.print(
                    f"\n[bold yellow]Description:[/]\n{f.get('message', 'No description')}"
                )
                console.print(
                    f"\n[bold green]Hardening suggestion:[/]\n{f.get('fix', 'No fix provided')}"
                )

                if Confirm.ask(
                    "Apply this fix automatically? (--fix not yet implemented)", default=False
                ):
                    console.print("[bold yellow]⚠️ Auto-fix is coming in Phase 5.[/]")
                    console.print("[dim]For now, please manually apply the suggested change.[/]")
                input("\nPress Enter to return to the dashboard...")
            else:
                console.print("[red]Invalid finding number.[/]")
        except ValueError:
            console.print("[red]Invalid input. Enter a number or 'q'.[/]")
