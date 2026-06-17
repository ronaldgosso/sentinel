cat > docs/adr/ADR-001-python.md << 'EOF'
# ADR-001: Programming Language

## Status
Accepted

## Context
We need a language that is widely adopted, has rich AST tooling, and is easy to distribute as a CLI tool and GitHub Action.

## Decision
Use **Python 3.10+**.

## Consequences
- Access to `ast`, `inspect`, and mature security libraries.
- Can distribute via PyPI and Docker.
- Must manage dependency conflicts (we'll use `uv`/poetry).
