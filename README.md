# Sentinel - AI-Powered Security Hardening

![Sentinel Logo](assets/logo.png)

[![PyPI version](https://badge.fury.io/py/sentinel-security.svg)](https://badge.fury.io/py/sentinel-security)
[![GitHub Actions](https://github.com/ronaldgosso/sentinel/workflows/CI/badge.svg)](https://github.com/ronaldgosso/sentinel/actions)
[![Docker Pulls](https://img.shields.io/docker/pulls/ronaldgosso/sentinel)](https://hub.docker.com/r/ronaldgosso/sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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
pip install sentinel-security

# Scan
sentinel scan .

# With AI (get a free key from Mistral AI)
export MISTRAL_API_KEY=your-key
sentinel scan . --ai
```

For full documentation, visit [Sentinel Docs](https://ronaldgosso.github.io/sentinel).

## Distribution

- PyPI: `pip install sentinel-security`
- Docker: `docker run ghcr.io/ronaldgosso/sentinel:latest scan .`
- GitHub Action: `uses: ronaldgosso/sentinel-action@v1`

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT

## Show your support

Give a star if this project helped you!
