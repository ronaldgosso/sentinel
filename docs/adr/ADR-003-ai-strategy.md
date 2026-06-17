# ADR-003: AI Provider Strategy

## Status
Accepted

## Context
We want to use Mistral to triage vulnerabilities, reduce false positives, and generate actionable hardening suggestions. Developers have varying needs: some require absolute privacy (offline), others want fastest performance (cloud API).

## Decision
Support **two modes** with a unified interface:

| Mode | Backend | Default? |
|------|---------|----------|
| **Local** | Ollama serving `mistral:7b-instruct` | Yes (if Ollama is installed and running) |
| **Cloud** | Mistral AI API (`mistral-tiny` or `mistral-small`) | Fallback / opt‑in via `--api-key` |

- **Prompt templates** are versioned and stored in `src/sentinel/ai/prompts/`.
- **Fallback** – if AI is unavailable or times out, use a rule‑based classifier (heuristics based on CWE, file type, and CVSS) so the scan never fails.

## Consequences
- Local mode is free, private, and works offline – perfect for security‑sensitive teams.
- Cloud mode is faster and more accurate – ideal for CI/CD.
- We must test prompt robustness to avoid hallucination – we'll maintain a test suite of known vulnerabilities.
- Ollama requires the user to pull the model – we'll print a clear error with installation instructions.