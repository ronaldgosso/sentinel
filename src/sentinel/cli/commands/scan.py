import os
import sys
from pathlib import Path
from typing import Any

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ... import __version__
from ...ai.client import VENDOR_CONFIGS
from ...ai.enricher import AIEnricher
from ...fixer.engine import apply_fix
from ...report.formatters import to_html, to_json, to_markdown, to_sarif
from ...scanners.dast.engine import DASTScanner
from ...scanners.sast.engine import SASTScanner
from ...scanners.sca.engine import SCAScanner

console = Console()


def run_scan(
    path: str, skip_sast: bool, skip_sca: bool, dast_url: str | None = None
) -> list[dict[str, Any]]:
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
@click.option(
    "--ai/--no-ai",
    "ai",
    default=None,
    help="Enable/disable AI analysis (prompts for credentials if needed)",
)
@click.option(
    "--ai-vendor",
    "--ai-provider",
    "ai_vendor",
    type=click.Choice(
        ["mistral", "openai", "anthropic", "gemini", "groq", "ollama"],
        case_sensitive=False,
    ),
    default=None,
    help="Choose AI vendor/provider (mistral, openai, anthropic, gemini, groq, ollama)",
)
@click.option(
    "--ai-backend",
    type=click.Choice(["local", "cloud"]),
    default=None,
    help="AI backend (cloud or local/ollama)",
)
@click.option(
    "--ai-api-key",
    help="API key for selected AI vendor (or set vendor env var)",
)
@click.option(
    "--ai-rate-limit",
    type=float,
    default=None,
    help="AI requests per second limit (optional)",
)
@click.option(
    "--ai-model",
    help="AI model override (e.g. mistral-small-latest, gpt-4o-mini, claude-3-5-haiku-20241022, gemini-1.5-flash)",
)
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
    "--output-format",
    type=click.Choice(["json", "sarif", "html", "markdown", "md"]),
    help="Export report format",
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
    ai: bool | None,
    ai_vendor: str | None,
    ai_backend: str | None,
    ai_api_key: str | None,
    ai_rate_limit: float | None,
    ai_model: str | None,
    ci: bool,
    skip_sast: bool,
    skip_sca: bool,
    dast: str | None,
    fix: bool,
    output_format: str | None,
    output_file: str | None,
    fail_on: str,
) -> None:
    """Scan a Python project for vulnerabilities."""
    target_path = Path(path).resolve()
    console.print(
        Panel.fit(
            f"[bold blue]🔍 Sentinel v{__version__}[/] – AI‑Powered Security Hardening",
            border_style="blue",
        )
    )

    if dast:
        console.print(f"DAST enabled: scanning [cyan]{dast}[/]")
    else:
        console.print(f"Scanning [cyan]{path}[/] ...")

    # Determine severity threshold for CI
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threshold = sev_order.get(fail_on, 3)

    # Determine AI assistance setting and credentials
    is_interactive = not ci and sys.stdin.isatty()
    has_any_key = any(
        os.getenv(cfg.get("env_key", ""))
        for cfg in VENDOR_CONFIGS.values()
        if cfg.get("env_key")
    )

    if ai is False:
        ai_enabled = False
    elif (
        ai is True
        or ai_vendor
        or ai_api_key
        or ai_model
        or ai_backend == "local"
        or has_any_key
    ):
        ai_enabled = True
    else:
        ai_enabled = False

    if ai_enabled:
        # Handle --ai-backend local
        if ai_backend == "local":
            ai_vendor = "ollama"

        # If vendor not specified, auto-detect or prompt in interactive mode
        if not ai_vendor:
            for v_name, v_info in VENDOR_CONFIGS.items():
                env_k = v_info.get("env_key")
                if env_k and os.getenv(env_k):
                    ai_vendor = v_name
                    break

            if not ai_vendor:
                if is_interactive and ai is True:
                    console.print("\n[bold cyan]🤖 AI Assistance Configuration[/]")
                    console.print(
                        "Supported AI vendors:\n"
                        "  • [bold]mistral[/]   - Mistral AI (Mistral-Small, Codestral)\n"
                        "  • [bold]openai[/]    - OpenAI (GPT-4o, GPT-4o-mini)\n"
                        "  • [bold]anthropic[/] - Anthropic (Claude 3.5 Sonnet / Haiku)\n"
                        "  • [bold]gemini[/]    - Google Gemini (Gemini 1.5 Flash / Pro)\n"
                        "  • [bold]groq[/]      - Groq Cloud (Llama 3.3)\n"
                        "  • [bold]ollama[/]    - Local Ollama (100% Offline)\n"
                    )
                    vendor_choice = Prompt.ask(
                        "Select AI vendor",
                        choices=["mistral", "openai", "anthropic", "gemini", "groq", "ollama", "none"],
                        default="mistral",
                    )
                    if vendor_choice == "none":
                        ai_enabled = False
                    else:
                        ai_vendor = vendor_choice
                else:
                    ai_vendor = "mistral"

        # If cloud vendor chosen, check if API key is provided or prompt
        if ai_enabled and ai_vendor and ai_vendor.lower() != "ollama":
            vendor_cfg = VENDOR_CONFIGS.get(ai_vendor.lower(), VENDOR_CONFIGS["mistral"])
            env_var = vendor_cfg.get("env_key")
            has_key = bool(ai_api_key or (env_var and os.getenv(env_var)))

            if not has_key and is_interactive:
                vendor_name = vendor_cfg.get("display_name", ai_vendor)
                key_input = Prompt.ask(
                    f"🔑 Enter {vendor_name} API Key (or press Enter to run without AI)",
                    password=True,
                    default="",
                ).strip()
                if key_input:
                    ai_api_key = key_input
                else:
                    console.print(
                        f"[yellow]No {vendor_name} key entered. Proceeding with standard scan.[/]"
                    )
                    ai_enabled = False

    if ci:
        console.print("[yellow]CI mode – running non-interactive scan.[/]")
        combined = run_scan(path, skip_sast=skip_sast, skip_sca=skip_sca, dast_url=dast)
        if ai_enabled:
            enricher = AIEnricher(
                api_key=ai_api_key,
                vendor=ai_vendor,
                use_local=(ai_backend == "local" or ai_vendor == "ollama"),
                rate_limit=ai_rate_limit,
                model=ai_model,
            )
            combined = enricher.enrich(combined)
        # Optionally apply fixes in CI mode (with --fix)
        if fix:
            for f in combined:
                apply_fix(f, dry_run=False, base_dir=target_path)
        # Export if requested
        if output_format:
            fmt = output_format
            ext = "md" if fmt in ("markdown", "md") else fmt
            out_file = output_file or f"sentinel-report.{ext}"
            if fmt == "json":
                to_json(combined, Path(out_file))
            elif fmt == "sarif":
                to_sarif(combined, Path(out_file))
            elif fmt == "html":
                to_html(combined, Path(out_file))
            elif fmt in ("markdown", "md"):
                to_markdown(combined, Path(out_file))
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

        if ai_enabled and combined:
            enricher = AIEnricher(
                api_key=ai_api_key,
                vendor=ai_vendor,
                use_local=(ai_backend == "local" or ai_vendor == "ollama"),
                rate_limit=ai_rate_limit,
                model=ai_model,
            )
            if enricher.available:
                ai_task = progress.add_task(
                    f"[magenta]AI ({enricher.client.vendor_name}): analysing findings...",
                    total=None,
                )
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
                    success = apply_fix(f, dry_run=False, base_dir=target_path)
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
                ext = "md" if fmt in ("markdown", "md") else fmt
                out_file = output_file or f"sentinel-report.{ext}"
                if fmt == "json":
                    to_json(combined, Path(out_file))
                elif fmt == "sarif":
                    to_sarif(combined, Path(out_file))
                elif fmt == "html":
                    to_html(combined, Path(out_file))
                elif fmt in ("markdown", "md"):
                    to_markdown(combined, Path(out_file))
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
                            success = apply_fix(f, dry_run=False, base_dir=target_path)
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
                        success = apply_fix(f, dry_run=False, base_dir=target_path)
                        if success:
                            console.print("[green]✅ Fix applied.[/]")
                        else:
                            console.print("[red]Failed to apply fix.[/]")
                    input("\nPress Enter to return to the dashboard...")
                else:
                    console.print("[red]Invalid finding number.[/]")
            except ValueError:
                console.print("[red]Invalid input. Enter a number, 'f', or 'q'.[/]")
