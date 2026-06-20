# Sentinel - AI-Powered Security Hardening

<img src="assets/logo.png" alt="Sentinel Logo" style="max-width: 100%; height: auto; display: block; margin: 0 auto 20px;">

[![PyPI version](https://badge.fury.io/py/sentinel-scanner.svg)](https://badge.fury.io/py/sentinel-scanner)
[![GitHub Actions](https://github.com/ronaldgosso/sentinel/workflows/CI/badge.svg)](https://github.com/ronaldgosso/sentinel/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Sentinel** is a developer-first CLI tool that finds security vulnerabilities in Python projects and provides AI-powered fixes - all in an interactive terminal dashboard.

---

## Features

- **SAST** - detects SQLi, XSS, command injection, hardcoded secrets, insecure crypto.
- **SCA** - checks dependencies against OSV.dev and NVD.
- **DAST** - optionally tests running web apps.
- **AI enrichment** (Mistral) - re-evaluates severity, explains attack scenarios, suggests fixes.
- **Interactive TUI** - no more grepping JSON logs.
- **Auto-fix** - applies safe remediations.
- **CI/CD ready** - GitHub Action, Docker, PyPI.

---

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

---

## Distribution & Running

- **PyPI**: `pip install sentinel-scanner`
- **Docker**: Run Sentinel in a containerized environment (details in [Docker README](docker/README.md)):
  ```bash
  docker run --rm -v $(pwd):/app ghcr.io/ronaldgosso/sentinel:latest scan .
  ```
- **GitHub Action**: Integrate into your workflows using `uses: ronaldgosso/sentinel-action@v1`.

---

## GitHub Actions / CI/CD Workflows

The repository uses automated GitHub Actions workflows to maintain code quality, build Docker images, publish PyPI releases, and host the documentation website:

| Workflow | File | Trigger | Description |
| :--- | :--- | :--- | :--- |
| **Continuous Integration (CI)** | [ci.yml](.github/workflows/ci.yml) | Push/PR to `main` | Runs tests, Ruff (linting), and Mypy (type checking) to ensure code meets quality standards before merge. |
| **Publish to PyPI** | [pypi-publish.yml](.github/workflows/pypi-publish.yml) | Push tag `v*.*.*` | Runs quality checks first. If successful, builds wheels and publishes the distribution packages to PyPI via secure OIDC. |
| **Build & Publish Docker** | [docker-build.yml](.github/workflows/docker-build.yml) | Push to `main`, tags `v*`, or PyPI success | Automates building the optimized multi-stage Python wheel Docker image and pushes tags (including `latest` and version numbers) to GHCR. |
| **Deploy Docs** | [docs.yml](.github/workflows/docs.yml) | Push to `main` | Deploys static files from the `website/` folder directly to GitHub Pages at [https://ronaldgosso.github.io/sentinel](https://ronaldgosso.github.io/sentinel). |

---

## Project Documentation & Useful Guides

Check out these documents to learn more about developing, building, and contributing to Sentinel:

* **[Docker Guide](docker/README.md)** - Details on running Sentinel via Docker, passing environment variables (like API keys), and exporting reports.
* **[Contributing Guidelines](CONTRIBUTING.md)** - Guide on repository setup, adding custom SAST/AST detectors, running tests, and the Pull Request/release process.
* **[Product Roadmap](ROADMAP.md)** - Overview of features planned for future releases (v1.1, v1.2, and v2.0).
* **[Security Policy](SECURITY.md)** - Instructions on how to report security vulnerabilities privately.
* **[Code of Conduct](CODE_OF_CONDUCT.md)** - Standards of behavior to ensure a welcoming community.

---

## License

This project is licensed under the **GPLv3** license. See the [LICENSE](LICENSE) file for details.

---

## Show your support

Give a star if this project helped you!
