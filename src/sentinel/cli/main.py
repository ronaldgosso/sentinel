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
from typing import Any

console = Console()


def combine_findings(sast_findings: Any, sca_findings: Any) -> Any:
    """Combine SAST and SCA findings into one list."""
    combined = []
    # SCA findings already have to_dict method
    for f in sca_findings:
        combined.append(f.to_dict())
    # SAST findings are of type Finding, convert to dict
    for f in sast_findings:
        combined.append(f.to_dict())
    return combined


def run_real_scan(path: str, ai_enabled: bool = True) -> Any:
    """Run SAST and SCA scanners."""
    # SAST
    scanner_sast = SASTScanner()
    sast_findings = scanner_sast.scan_directory(path)

    # SCA
    scanner_sca = SCAScanner()
    sca_findings = scanner_sca.scan_directory(path)

    combined = combine_findings(sast_findings, sca_findings)

    # Count by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in combined:
        sev = f["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["Medium"] += 1  # fallback

    # Summary panel
    summary = Panel(
        f"[bold red]🔴 Critical: {severity_counts['Critical']}[/]   "
        f"[bold orange1]🟠 High: {severity_counts['High']}[/]   "
        f"[bold yellow]🟡 Medium: {severity_counts['Medium']}[/]   "
        f"[bold green]🟢 Low: {severity_counts['Low']}[/]",
        title=f"Vulnerability Summary ({len(combined)} total)",
        border_style="bright_blue",
    )
    console.print(summary)

    if not combined:
        console.print("[bold green]✅ No security issues found![/]")
        return []

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
        else:
            type_display = f["id"].replace("_", " ").title()
        ai_mark = "✅" if f.get("ai_confirmed", False) else "❌"
        # Location display
        loc = f["location"]
        if ":" in loc:
            # file:line format maybe
            parts = loc.split(":")
            if len(parts) >= 2 and parts[-1].isdigit():
                loc_file = Path(parts[0]).name
                loc_line = parts[-1]
            else:
                loc_file = Path(loc).name
                loc_line = str(f.get("line", ""))
        else:
            loc_file = Path(loc).name
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
    return combined


def show_detail(findings: Any, idx: int) -> None:
    """Drill-down for a specific finding."""
    if idx < 1 or idx > len(findings):
        console.print("[red]Invalid finding number.[/]")
        return
    f = findings[idx - 1]

    sev_color = (
        "red"
        if f["severity"] == "Critical"
        else "orange1"
        if f["severity"] == "High"
        else "yellow"
        if f["severity"] == "Medium"
        else "green"
    )
    console.rule(f"[bold]🔎 Finding #{idx} – {f['id'].replace('_', ' ').title()}[/]")
    console.print(f"[bold]Severity:[/] [{sev_color}]{f['severity']}[/]")
    console.print(f"[bold]Location:[/] {f['location']}")
    if f.get("line"):
        console.print(f"[bold]Line:[/] {f['line']}")
    console.print(f"[bold]CWE:[/] {f.get('cwe', 'N/A')}")
    console.print(f"[bold]Code snippet:[/]\n[italic cyan]{f.get('code', 'N/A')}[/]")
    console.print(f"\n[bold yellow]Description:[/]\n{f.get('message', 'No description')}")
    console.print(f"\n[bold green]Hardening suggestion:[/]\n{f.get('fix', 'No fix provided')}")

    if Confirm.ask("Apply this fix automatically? (--fix not yet implemented)", default=False):
        console.print("[bold yellow]⚠️ Auto-fix is coming in Phase 5.[/]")
        console.print("[dim]For now, please manually apply the suggested change.[/]")

    input("\nPress Enter to return to the dashboard...")


@click.command()  # type: ignore[misc]
@click.argument("path", default=".", type=click.Path(exists=True))  # type: ignore[misc]
@click.option("--ai/--no-ai", default=True, help="Enable/disable AI analysis (Phase 4)")  # type: ignore[misc]
@click.option("--ci", is_flag=True, help="CI mode – non-interactive, exit with code")  # type: ignore[misc]
@click.option("--skip-sast", is_flag=True, help="Skip SAST scanning")  # type: ignore[misc]
@click.option("--skip-sca", is_flag=True, help="Skip SCA scanning")  # type: ignore[misc]
def cli(path: str, ai: bool, ci: bool, skip_sast: bool, skip_sca: bool) -> None:
    """Sentinel – AI-Powered Security Hardening."""
    console.print(
        Panel.fit(
            "[bold blue]🔍 Sentinel v0.1.0[/] – AI‑Powered Security Hardening", border_style="blue"
        )
    )
    console.print(f"Scanning [cyan]{path}[/] ...")

    if ci:
        console.print("[yellow]CI mode – running non-interactive scan.[/]")
        # We'll still run both, but exit based on findings
        combined = run_scan(
            path, ai_enabled=ai, skip_sast=skip_sast, skip_sca=skip_sca, progress=False
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

        # Actually run the scan (this will take time)
        combined = run_scan(
            path, ai_enabled=ai, skip_sast=skip_sast, skip_sca=skip_sca, progress=False
        )

        for task in tasks:
            progress.update(task, completed=True)

        if ai:
            t_ai = progress.add_task(
                "[magenta]AI: Mistral analysing findings... (Phase 4)", total=None
            )
            time.sleep(0.5)
            progress.update(t_ai, completed=True)

    if not combined:
        return

    while True:
        choice = Prompt.ask("Enter #[bold]#[/] to see details, or [bold]q[/] to quit", default="q")
        if choice.lower() == "q":
            export = Confirm.ask("Save a report? (JSON/SARIF/HTML)", default=False)
            if export:
                # Placeholder – Phase 5 will implement actual export
                console.print("[green]Report saved as sentinel-report.json[/] (mock)")
            console.print("[bold]👋 Goodbye! Stay secure.[/]")
            break
        try:
            fidx = int(choice)
            show_detail(combined, fidx)
        except ValueError:
            console.print("[red]Invalid input. Enter a number or 'q'.[/]")


def run_scan(
    path: str, ai_enabled: bool, skip_sast: bool, skip_sca: bool, progress: bool = True
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
    return combined
