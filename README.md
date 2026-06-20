# Sentinel - AI-Powered Security Hardening

<img src="assets/logo.png" alt="Sentinel Logo" style="max-width: 100%; height: auto; display: block; margin: 0 auto 20px;">

[![PyPI version](https://badge.fury.io/py/sentinel-scanner.svg)](https://badge.fury.io/py/sentinel-scanner)
[![GitHub Actions](https://github.com/ronaldgosso/sentinel/workflows/CI/badge.svg)](https://github.com/ronaldgosso/sentinel/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Sentinel** is a developer-first CLI tool that finds security vulnerabilities in Python projects and provides AI-powered fixes - all in an interactive terminal dashboard.

## Features

- **SAST** - detects SQLi, XSS, command injection, hardcoded secrets, insecure crypto.
- **SCA** - checks dependencies against OSV.dev and NVD.
- **DAST** - optionally tests running web apps.
- **AI enrichment** (Mistral) - re-evaluates severity, explains attack scenarios, suggests fixes.
- **Interactive TUI** - no more grepping JSON logs.
- **Auto-fix** - applies safe remediations.
- **CI/CD ready** - GitHub Action, Docker, PyPI.

## Quick Start

```bash
# Install
pip install sentinel-scanner

# Scan
sentinel scan .

# With AI (get a free key from Mistral AI)
export MISTRAL_API_KEY=your-key
sentinel scan . --ai
```

For full documentation, visit [Sentinel Docs](https://ronaldgosso.github.io/sentinel).

## Distribution

- PyPI: `pip install sentinel-scanner`
- Docker: `docker run ghcr.io/ronaldgosso/sentinel:latest scan .`
- GitHub Action: `uses: ronaldgosso/sentinel-action@v1`

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-3.0

## Show your support

Give a star if this project helped you!
