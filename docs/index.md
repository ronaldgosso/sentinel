# Sentinel - AI-Powered Security Hardening

**Sentinel** is a developer-first CLI tool that detects vulnerabilities in Python projects using static (SAST), dependency (SCA), and dynamic (DAST) scanning - all enhanced by AI (Mistral) to prioritise and explain fixes.

## Key Features

- **SAST** - scans source code for SQLi, XSS, command injection, hardcoded secrets, and insecure crypto.
- **SCA** - checks dependencies against OSV.dev and NVD, with CVSS scoring.
- **DAST** - optionally tests running web applications for injection and header issues.
- **AI-powered** - Mistral re-evaluates severity, suggests specific fixes, and explains attack scenarios.
- **Interactive TUI** - no need to read JSON logs; drill down into each finding.
- **CI/CD ready** - GitHub Action, Docker, and PyPI distribution.

## Quick Start

```bash
# Install via pip
pip install sentinel-security

# Scan your project
sentinel scan .

# With AI (requires Mistral API key)
export MISTRAL_API_KEY=your-key
sentinel scan . --ai

# Generate a report
sentinel scan . --output-format html --output-file report.html
```

For more details, see the [Installation](installation.md) guide.
