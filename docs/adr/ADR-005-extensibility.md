# ADR-005: Extensibility

## Status
Accepted

## Context
Security rules evolve quickly. We cannot hard‑code every detector. Also, teams may want to add organisation‑specific rules (e.g., no usage of internal APIs).

## Decision
- **Rule engine:** YAML‑defined rules with a schema that includes:
  - `id`, `name`, `cwe`, `severity`
  - `pattern` (for AST matching) or `regex` (for simple text)
  - `message` and `remediation` template
- **Plugin hooks:** Users can write Python modules under `~/.sentinel/plugins/` that implement a `detect(file_content, ast_node)` function.
- **Built‑in rules** are stored in `rules/` and shipped with the package – they can be overridden by user rules.
- **Exclusions:** `.sentinelignore` file (gitignore‑style) to skip test files, migrations, etc.

## Consequences
- We reduce maintenance burden – community can contribute rules.
- Custom rules make Sentinel valuable for enterprises with internal compliance checks.
- We must validate YAML rules at startup to avoid runtime crashes – schema validation with `pydantic`.
- Plugins run in a sandbox? For v1, we trust the user – we'll document security implications.