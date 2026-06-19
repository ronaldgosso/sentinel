import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import box
from pathlib import Path

from ...scanners.sast.engine import SASTScanner
from ...scanners.sca.engine import SCAScanner
from ...scanners.dast.engine import DASTScanner
from ...ai.enricher import AIEnricher
from ...report.formatters import to_json, to_sarif, to_html
from ...fixer.engine import apply_fix
from typing import List, Dict, Any, Optional

console = Console()


def run_scan(
    path: str, skip_sast: bool, skip_sca: bool, dast_url: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Orchestrate scanning without AI, return combined findings."""
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


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--ai/--no-ai", default=True, help="Enable/disable AI analysis")
@click.option(
    "--ai-backend", type=click.Choice(["local", "cloud"]), default="cloud", help="AI backend"
)
@click.option("--ai-api-key", help="Mistral API key (optional, overrides env)")
@click.option("--ci", is_flag=True, help="CI mode – non-interactive, exit with code")
@click.option("--skip-sast", is_flag=True, help="Skip SAST scanning")
@click.option("--skip-sca", is_flag=True, help="Skip SCA scanning")
@click.option("--dast", help="Enable DAST scanning against the given target URL")
@click.option(
    "--fix",
    is_flag=True,
    help="Apply auto-fixes (interactive) or in CI mode apply all possible fixes",
)
@click.option(
    "--output-format", type=click.Choice(["json", "sarif", "html"]), help="Export report format"
)
@click.option("--output-file", help="Output file for report (default: sentinel-report.<format>)")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="high",
    help="Fail CI if any finding at or above this severity is found",
)
def scan(
    path: str,
    ai: bool,
    ai_backend: str,
    ai_api_key: Optional[str],
    ci: bool,
    skip_sast: bool,
    skip_sca: bool,
    dast: Optional[str],
    fix: bool,
    output_format: Optional[str],
    output_file: Optional[str],
    fail_on: str,
) -> None:
    """Scan a Python project for vulnerabilities."""
    console.print(
        Panel.fit(
            "[bold blue]🔍 Sentinel v0.1.0[/] – AI‑Powered Security Hardening", border_style="blue"
        )
    )

    if dast:
        console.print(f"DAST enabled: scanning [cyan]{dast}[/]")
    else:
        console.print(f"Scanning [cyan]{path}[/] ...")

    # Determine severity threshold for CI
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threshold = sev_order.get(fail_on, 3)

    if ci:
        console.print("[yellow]CI mode – running non-interactive scan.[/]")
        combined = run_scan(path, skip_sast=skip_sast, skip_sca=skip_sca, dast_url=dast)
        if ai:
            enricher = AIEnricher(api_key=ai_api_key, use_local=(ai_backend == "local"))
            combined = enricher.enrich(combined)
        # Optionally apply fixes in CI mode (with --fix)
        if fix:
            for f in combined:
                apply_fix(f, dry_run=False)
        # Export if requested
        if output_format:
            fmt = output_format
            out_file = output_file or f"sentinel-report.{fmt}"
            if fmt == "json":
                to_json(combined, Path(out_file))
            elif fmt == "sarif":
                to_sarif(combined, Path(out_file))
            elif fmt == "html":
                to_html(combined, Path(out_file))
            console.print(f"[green]Report saved to {out_file}[/]")
        # Check severity threshold
        fail_severities = [k for k, v in sev_order.items() if v >= threshold]
        critical_high = [f for f in combined if f.get("severity", "").lower() in fail_severities]
        console.print(
            f"✅ Scan complete. Found {len(critical_high)} issues with severity >= {fail_on}."
        )
        if critical_high:
            raise SystemExit(1)
        else:
            raise SystemExit(0)

    # Interactive flow
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

        combined = run_scan(path, skip_sast=skip_sast, skip_sca=skip_sca, dast_url=dast)

        for task in tasks:
            progress.update(task, completed=True)

        if ai and combined:
            ai_task = progress.add_task("[magenta]AI: Mistral analysing findings...", total=None)
            enricher = AIEnricher(api_key=ai_api_key, use_local=(ai_backend == "local"))
            combined = enricher.enrich(combined)
            progress.update(ai_task, completed=True)

    # Apply fixes if --fix is given (interactive)
    if fix and combined:
        console.print("[bold]Auto-fix mode:[/] Will apply fixes for each finding.")
        for idx, f in enumerate(combined, 1):
            if f.get("fix"):
                console.print(f"Finding #{idx}: {f.get('id')} at {f.get('location')}")
                fix_str = str(f.get("fix", ""))
                if Confirm.ask(f"Apply fix: {fix_str[:100]}...", default=False):
                    success = apply_fix(f, dry_run=False)
                    if success:
                        console.print("[green]✅ Fix applied.[/]")
                    else:
                        console.print("[red]Failed to apply fix.[/]")

    # Display results
    if not combined:
        console.print("[bold green]✅ No security issues found![/]")
        return

    # Count by severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in combined:
        sev = str(f.get("severity", "Medium"))
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
            if f.get("severity") == "Critical"
            else "orange1"
            if f.get("severity") == "High"
            else "yellow"
            if f.get("severity") == "Medium"
            else "green"
        )
        # Type
        if "sca" in f.get("id", ""):
            type_display = "SCA Vulnerability"
        elif "dast" in f.get("id", ""):
            type_display = "DAST Vulnerability"
        else:
            type_display = f.get("id", "Unknown").replace("_", " ").title()
        ai_mark = "✅" if f.get("ai_confirmed", False) else "❌"
        loc = f.get("location", "")
        loc_display = Path(loc).name if ":" not in loc else loc[:20]
        line_display = str(f.get("line", ""))
        table.add_row(
            str(idx),
            f"[{sev_color}]{f.get('severity', 'Medium')}[/]",
            type_display[:20],
            loc_display[:20],
            line_display,
            ai_mark,
        )
    console.print(table)

    # Drill-down loop
    while True:
        choice = Prompt.ask(
            "Enter #[bold]#[/] to see details, [bold]f[/] to apply fix, or [bold]q[/] to quit",
            default="q",
        )
        if choice.lower() == "q":
            # Export if requested
            if output_format:
                fmt = output_format
                out_file = output_file or f"sentinel-report.{fmt}"
                if fmt == "json":
                    to_json(combined, Path(out_file))
                elif fmt == "sarif":
                    to_sarif(combined, Path(out_file))
                elif fmt == "html":
                    to_html(combined, Path(out_file))
                console.print(f"[green]Report saved to {out_file}[/]")
            console.print("[bold]👋 Goodbye! Stay secure.[/]")
            break
        elif choice.lower() == "f":
            # Apply fix to all? or we can select a specific finding
            # For simplicity, we'll ask for a number
            fidx = Prompt.ask("Enter finding number to fix", default="")
            if fidx.isdigit():
                idx = int(fidx)
                if 1 <= idx <= len(combined):
                    f = combined[idx - 1]
                    if f.get("fix"):
                        console.print(f"Applying fix for finding #{idx}:")
                        console.print(f"[bold]Original fix suggestion:[/] {f.get('fix')}")
                        if Confirm.ask("Apply this fix?", default=False):
                            success = apply_fix(f, dry_run=False)
                            if success:
                                console.print("[green]✅ Fix applied.[/]")
                            else:
                                console.print("[red]Failed to apply fix.[/]")
                    else:
                        console.print("[yellow]No fix available for this finding.[/]")
                else:
                    console.print("[red]Invalid number.[/]")
            else:
                console.print("[red]Invalid input. Enter a number.[/]")
        else:
            try:
                idx = int(choice)
                if 1 <= idx <= len(combined):
                    f = combined[idx - 1]
                    sev_color = (
                        "red"
                        if f.get("severity") == "Critical"
                        else "orange1"
                        if f.get("severity") == "High"
                        else "yellow"
                        if f.get("severity") == "Medium"
                        else "green"
                    )
                    console.rule(
                        f"[bold]🔎 Finding #{idx} – {f.get('id', 'Unknown').replace('_', ' ').title()}[/]"
                    )
                    console.print(
                        f"[bold]Severity:[/] [{sev_color}]{f.get('severity', 'Medium')}[/]"
                    )
                    console.print(f"[bold]Location:[/] {f.get('location', 'N/A')}")
                    if f.get("line"):
                        console.print(f"[bold]Line:[/] {f['line']}")
                    console.print(f"[bold]CWE:[/] {f.get('cwe', 'N/A')}")
                    console.print(f"[bold]Code snippet:[/]\n[italic cyan]{f.get('code', 'N/A')}[/]")
                    console.print(
                        f"\n[bold yellow]Description:[/]\n{f.get('message', 'No description')}"
                    )
                    if f.get("attack_scenario"):
                        console.print(f"\n[bold red]Attack scenario:[/]\n{f['attack_scenario']}")
                    if f.get("justification"):
                        console.print(f"\n[bold cyan]AI Justification:[/] {f['justification']}")
                    console.print(
                        f"\n[bold green]Hardening suggestion:[/]\n{f.get('fix', 'No fix provided')}"
                    )

                    if f.get("fix") and Confirm.ask("Apply this fix now?", default=False):
                        success = apply_fix(f, dry_run=False)
                        if success:
                            console.print("[green]✅ Fix applied.[/]")
                        else:
                            console.print("[red]Failed to apply fix.[/]")
                    input("\nPress Enter to return to the dashboard...")
                else:
                    console.print("[red]Invalid finding number.[/]")
            except ValueError:
                console.print("[red]Invalid input. Enter a number, 'f', or 'q'.[/]")
