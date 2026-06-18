# ADR-003: AI Provider Strategy

## Status
Accepted

## Context
We want to use Mistral to triage vulnerabilities, reduce false positives, and generate actionable hardening suggestions. Developers have varying needs: some require absolute privacy (offline), others want fastest performance (cloud API).

## Decision
Support **two modes** with a unified interface:

| Mode | Backend | Default? |
|------|---------|----------|
| **Cloud** | Mistral AI API (`mistral-tiny` or `mistral-small`) | Yes (requires API key) |
| **Local** | Ollama serving `mistral:7b-instruct` | Opt-in via `--ai-backend local` |

- **Cloud API** is the primary, recommended backend due to reliability and speed.
- **Local Ollama** is an optional fallback for development or air-gapped environments.
- **Prompt templates** are versioned and stored in `src/sentinel/ai/prompts/`.
- **Fallback** – if AI is unavailable or times out, use a rule‑based classifier (heuristics based on CWE, file type, and CVSS) so the scan never fails.

## Consequences
- Cloud mode is faster and more accurate – ideal for CI/CD.
- Users must obtain a Mistral API key (free tier available).
- We add clear error messages and a prompt to guide users.
- Local mode is free, private, and works offline – perfect for security‑sensitive teams.
- Ollama requires the user to pull the model – we'll print a clear error with installation instructions.