# ADR-007: Distribution

## Status
Accepted

## Context
Developers install tools in different ways: via package managers, containers, or CI/CD marketplaces. We need maximum reach with minimal friction.

## Decision
Ship Sentinel through **three channels**, all built from the same source:

| Channel | Method | Primary Audience |
|---------|--------|-------------------|
| **PyPI** | `pip install sentinel-security` | Local development |
| **Docker Hub** | `docker run sentinel/security-scanner` | CI runners, ephemeral environments |
| **GitHub Action** | `uses: sentinel/security-action@v1` | GitHub‑native CI/CD |

- The GitHub Action wraps the Docker image internally – so we maintain one container image.
- Versioning: follow SemVer; `latest` tag points to the most recent stable release.
- PyPI package includes the CLI and all rules – Docker image includes Ollama pre‑configured (but not the model, to keep size small).

## Consequences
- Three distribution targets triple our release engineering effort – we'll automate with GitHub Actions (build, test, publish on tag).
- Docker image size must stay under 300MB – we'll use Alpine base and exclude dev dependencies.
- The GitHub Action will support inputs: `fail-on-severity`, `ai-enabled`, `api-key`, `export-sarif`.
- We'll provide a one‑line install script for non‑Python users: `curl -sSL https://sentinel.dev/install.sh | sh` (future).