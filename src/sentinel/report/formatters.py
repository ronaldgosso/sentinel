import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


def to_json(findings: List[Dict[str, Any]], output_file: Path) -> None:
    """Write findings to a JSON file."""
    data = {
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)


def to_sarif(findings: List[Dict[str, Any]], output_file: Path) -> None:
    """Convert findings to SARIF v2.1.0 format."""
    # SARIF structure
    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "version": "0.1.0",
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
                "defaultConfiguration": {"level": f.get("severity", "medium").lower()},
                "help": {"text": f.get("fix", "")},
            }
    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules_map.values())

    # Results
    results = []
    for f in findings:
        result = {
            "ruleId": f.get("id", "unknown"),
            "level": f.get("severity", "medium").lower(),
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


def to_html(findings: List[Dict[str, Any]], output_file: Path) -> None:
    """Generate a self-contained HTML report."""
    html_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Sentinel Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; }
        .summary { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .stat { padding: 10px 20px; border-radius: 6px; font-weight: bold; }
        .critical { background: #e74c3c; color: white; }
        .high { background: #e67e22; color: white; }
        .medium { background: #f1c40f; color: #333; }
        .low { background: #2ecc71; color: white; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #34495e; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .sev-critical { background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; }
        .sev-high { background: #e67e22; color: white; padding: 2px 8px; border-radius: 4px; }
        .sev-medium { background: #f1c40f; color: #333; padding: 2px 8px; border-radius: 4px; }
        .sev-low { background: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; }
        .fix { background: #ecf0f1; padding: 10px; border-left: 4px solid #3498db; margin: 10px 0; }
        .footer { margin-top: 30px; color: #7f8c8d; font-size: 0.9em; text-align: center; }
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
    <div class="footer">Reported by Sentinel v0.1.0</div>
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
        location = (
            Path(f.get("location", "")).name
            if ":" not in f.get("location", "")
            else f.get("location", "")
        )
        fix = f.get("fix", "").replace("\n", "<br>")
        rows += f"""
        <tr>
            <td>{idx}</td>
            <td><span class="{sev_class}">{sev}</span></td>
            <td>{f.get('id', '').replace('_', ' ').title()}</td>
            <td>{location}</td>
            <td>{f.get('line', '')}</td>
            <td><div class="fix">{fix}</div></td>
        </tr>
        """

    html_content = html_template.format(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        critical=counts["Critical"],
        high=counts["High"],
        medium=counts["Medium"],
        low=counts["Low"],
        rows=rows,
    )
    with open(output_file, "w", encoding="utf-8") as file:
        file.write(html_content)
