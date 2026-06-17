# ADR-006: Execution Model

## Status
Accepted

## Context
Sentinel must scan large monorepos (100K+ LOC) quickly, handle network I/O (OSV/NVD/AI), and remain responsive in the TUI.

## Decision
- **CLI framework:** `click` with subcommands (`scan`, `fix`, `init`, `update-db`).
- **Concurrency:**
  - SAST: `multiprocessing.Pool` over Python files – each worker parses AST independently.
  - SCA: `asyncio` + `httpx` for concurrent API requests to OSV.
  - DAST: sequential with delays (to avoid rate‑limiting / DoS on target).
- **Progress:** `rich.progress` with live updates for each stage.
- **Cancellation:** `CTRL+C` gracefully interrupts and prints partial results.

## Consequences
- Multiprocessing adds overhead for small projects – we'll auto‑detect file count and fallback to single‑thread if < 50 files.
- Async SCA significantly speeds up dependency checks – we cache results to avoid repeated network calls.
- DAST is optional and off by default – user must pass `--dast` flag to enable.
- We must handle file locking and temporary directories safely.