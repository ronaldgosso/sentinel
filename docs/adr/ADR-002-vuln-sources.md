# ADR-002: Vulnerability Data Sources

## Status
Accepted

## Context
We need authoritative, up‑to‑date vulnerability databases for SCA (dependency scanning) and CVE enrichment. The data must be available offline after initial cache.

## Decision
- **Primary source:** OSV.dev REST API (comprehensive, low latency, supports multiple ecosystems).
- **Secondary source:** NVD API – only for CVSS v3.1 scores and exploitability metrics.
- **Fallback:** Safety DB metadata (via `safety` package) for known malicious packages not yet in OSV.
- **Cache:** Local SQLite database. Refresh automatically every 24h on first scan; user can force with `sentinel update-db`.

## Consequences
- OSV covers PyPI, npm, Go, etc. – we start with PyPI only, but can expand.
- We respect OSV’s fair‑use rate limits – implement exponential backoff and local cache to minimise calls.
- NVD API sometimes has downtime – we gracefully fall back to OSV’s own severity when NVD is unreachable.
- Safety DB is used as a last resort – we parse its JSON output to fill gaps.