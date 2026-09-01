import html as html_module
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__


def _sarif_level(severity: str) -> str:
    """Map finding severity to SARIF-compliant level.

    SARIF 2.1.0 only allows: error, warning, note, none.
    """
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity.lower(), "warning")


def to_json(findings: list[dict[str, Any]], output_file: Path) -> None:
    """Write findings to a JSON file."""
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)


def to_sarif(findings: list[dict[str, Any]], output_file: Path) -> None:
    """Convert findings to SARIF v2.1.0 format."""
    # SARIF structure
    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": __version__,
                        "informationUri": "https://github.com/ronaldgosso/sentinel",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }
    # We'll build rules and results from findings
    rules_map = {}
    for f in findings:
        rule_id = f.get("id", "unknown")
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_id.replace("_", " ").title()},
                "fullDescription": {"text": f.get("message", "")},
                "defaultConfiguration": {"level": _sarif_level(f.get("severity", "Medium"))},
                "help": {"text": f.get("fix", "")},
            }
    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())

    # Results
    results = []
    for f in findings:
        result = {
            "ruleId": f.get("id", "unknown"),
            "level": _sarif_level(f.get("severity", "Medium")),
            "message": {"text": f.get("message", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("location", "")},
                        "region": {"startLine": f.get("line", 1)},
                    }
                }
            ],
        }
        results.append(result)
    sarif["runs"][0]["results"] = results

    with open(output_file, "w") as file:
        json.dump(sarif, file, indent=2)


def to_html(findings: list[dict[str, Any]], output_file: Path) -> None:
    """Generate a self-contained HTML report."""
    html_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Sentinel Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .stat {{ padding: 10px 20px; border-radius: 6px; font-weight: bold; }}
        .critical {{ background: #e74c3c; color: white; }}
        .high {{ background: #e67e22; color: white; }}
        .medium {{ background: #f1c40f; color: #333; }}
        .low {{ background: #2ecc71; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; border: 1px solid #ddd; text-align: left; }}
        th {{ background: #34495e; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .sev-critical {{ background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; }}
        .sev-high {{ background: #e67e22; color: white; padding: 2px 8px; border-radius: 4px; }}
        .sev-medium {{ background: #f1c40f; color: #333; padding: 2px 8px; border-radius: 4px; }}
        .sev-low {{ background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; }}
        .fix {{ background: #ecf0f1; padding: 10px; border-left: 4px solid #3498db; margin: 10px 0; }}
        .footer {{ margin-top: 30px; color: #7f8c8d; font-size: 0.9em; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 Sentinel Security Report</h1>
    <p>Generated: {generated_at}</p>
    <div class="summary">
        <div class="stat critical">Critical: {critical}</div>
        <div class="stat high">High: {high}</div>
        <div class="stat medium">Medium: {medium}</div>
        <div class="stat low">Low: {low}</div>
    </div>
    <table>
        <thead><tr><th>#</th><th>Severity</th><th>Type</th><th>Location</th><th>Line</th><th>Fix</th></tr></thead>
        <tbody>
            {rows}
        </tbody>
    </table>
    <div class="footer">Reported by Sentinel v{version}</div>
</div>
</body>
</html>"""
    # Count severity
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Medium")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Medium"] += 1

    # Build table rows
    rows = ""
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "Medium")
        sev_class = f"sev-{sev.lower()}"
        raw_location = f.get("location", "")
        location = Path(raw_location).name if ":" not in raw_location else raw_location
        fix = html_module.escape(f.get("fix", "")).replace("\n", "<br>")
        escaped_id = html_module.escape(f.get("id", "").replace("_", " ").title())
        escaped_location = html_module.escape(str(location))
        rows += f"""
        <tr>
            <td>{idx}</td>
            <td><span class="{html_module.escape(sev_class)}">{html_module.escape(sev)}</span></td>
            <td>{escaped_id}</td>
            <td>{escaped_location}</td>
            <td>{html_module.escape(str(f.get('line', '')))}</td>
            <td><div class="fix">{fix}</div></td>
        </tr>
        """

    html_content = html_template.format(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        critical=counts["Critical"],
        high=counts["High"],
        medium=counts["Medium"],
        low=counts["Low"],
        rows=rows,
        version=__version__,
    )
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)


def to_markdown(findings: list[dict[str, Any]], output_file: Path) -> None:
    """Generate a GitHub-flavored Markdown report suitable for PR comments and GitHub step summaries."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = str(f.get("severity", "Medium")).capitalize()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Medium"] += 1

    total = len(findings)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    status_badge = (
        f"🔴 **Vulnerabilities Detected ({total} total)**"
        if total > 0
        else "🟢 **No Security Issues Detected**"
    )

    md = [
        "## 🔍 Sentinel Security Scan Report",
        "",
        f"> **Status:** {status_badge}  ",
        f"> **Scan Time:** `{timestamp}` | **Engine:** Sentinel v{__version__}",
        "",
        "### 📊 Severity Summary",
        "",
        "| 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |",
        "| :---: | :---: | :---: | :---: |",
        f"| **{counts['Critical']}** | **{counts['High']}** | **{counts['Medium']}** | **{counts['Low']}** |",
        "",
    ]

    if not findings:
        md.extend(
            [
                "### ✅ Scan Clean",
                "No security vulnerabilities or policy violations were detected in this repository.",
                "",
                "---",
                "*Report generated by [Sentinel](https://github.com/ronaldgosso/sentinel) AI Security Hardening.*",
            ]
        )
        with open(output_file, "w", encoding="utf-8") as out_clean:
            out_clean.write("\n".join(md) + "\n")
        return

    md.extend(
        [
            "### 🛡️ Findings Overview",
            "",
            "| # | Severity | Vulnerability | Location | Line | AI Analysis |",
            "| :-: | :--- | :--- | :--- | :-: | :-: |",
        ]
    )

    sev_icons = {
        "critical": "🔴 Critical",
        "high": "🟠 High",
        "medium": "🟡 Medium",
        "low": "🟢 Low",
    }

    for idx, f in enumerate(findings, 1):
        sev = str(f.get("severity", "Medium"))
        sev_label = sev_icons.get(sev.lower(), sev)
        vuln_type = str(f.get("id", "Unknown")).replace("_", " ").title()
        loc = str(f.get("location", "N/A"))
        line_val = str(f.get("line", "-"))
        ai_status = "✅ Confirmed" if f.get("ai_confirmed") else "ℹ️ Offline Rule"
        md.append(
            f"| {idx} | {sev_label} | **{vuln_type}** | `{loc}` | `{line_val}` | {ai_status} |"
        )

    md.extend(
        [
            "",
            "<details>",
            "<summary><b>🔎 Detailed Findings & AI Remediation Recommendations</b></summary>",
            "",
        ]
    )

    for idx, f in enumerate(findings, 1):
        vuln_type = str(f.get("id", "Unknown")).replace("_", " ").title()
        sev = str(f.get("severity", "Medium"))
        loc = str(f.get("location", "N/A"))
        line = f.get("line")
        loc_str = f"`{loc}:{line}`" if line else f"`{loc}`"
        raw_cwe = f.get("cwe")
        cwe = str(raw_cwe) if raw_cwe else None
        cwe_str = (
            f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)"
            if cwe and cwe != "N/A"
            else "N/A"
        )

        md.extend(
            [
                f"#### #{idx} {vuln_type} — `{sev}`",
                f"- **Location:** {loc_str}",
                f"- **CWE:** {cwe_str}",
                f"- **Description:** {f.get('message', 'No description')}",
            ]
        )

        if f.get("code") and f.get("code") != "N/A":
            md.extend(
                [
                    "- **Vulnerable Code:**",
                    "```python",
                    f"{f['code']}",
                    "```",
                ]
            )

        if f.get("attack_scenario"):
            md.extend(
                [
                    f"- **Attack Scenario:** {f['attack_scenario']}",
                ]
            )

        if f.get("justification"):
            md.extend(
                [
                    f"- **AI Risk Justification:** {f['justification']}",
                ]
            )

        if f.get("fix"):
            md.extend(
                [
                    "- **💡 Hardening Suggestion:**",
                    "```python",
                    f"{f['fix']}",
                    "```",
                ]
            )

        md.append("")

    md.extend(
        [
            "</details>",
            "",
            "---",
            "*Report generated by [Sentinel](https://github.com/ronaldgosso/sentinel) AI Security Hardening.*",
        ]
    )

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(md) + "\n")
