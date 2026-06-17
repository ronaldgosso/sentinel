# ADR-004: Output & Reporting

## Status
Accepted

## Context
Existing tools (Bandit, Safety) dump JSON/XML and force developers to grep through logs. This creates friction and ignores findings. Sentinel must be **human‑first**, making security insights immediately actionable without requiring external tools.

## Decision
- **Primary interface:** Interactive TUI built with `rich` – progressive disclosure:
  1. Summary banner (counts by severity).
  2. Sortable/filterable table of findings.
  3. Drill‑down per finding → full attack scenario + AI fix + one‑click apply (`--fix`).
  4. Optional export at the very end.
- **Export formats** (for CI/CD and compliance): JSON, SARIF (GitHub Code Scanning), HTML. These are **never** shown by default – only generated on request or via `--export` flag.
- **CI/CD mode** (`--ci`): non‑interactive, prints a concise summary to stdout, exits with code based on severity threshold (e.g., fail on Critical/High).

## Consequences
- Developers will actually read and fix issues because the experience is pleasant.
- We invest more effort in TUI than in report formatting – but that's intentional.
- SARIF output enables native GitHub integration – we'll follow the SARIF v2.1.0 spec.
- The HTML report will be a self‑contained page with charts and fix recommendations – useful for sharing with managers.