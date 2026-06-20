# Sentinel - AI-Powered Security Hardening

<p align="center">
  <img width="300" height="300" alt="Sentinel Logo" src="https://github.com/user-attachments/assets/f9afe362-bb21-41df-a3f0-23325c8316fd" />
</p>

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

## Vulnerability Detection & Offline Remediations

Sentinel works fully out-of-the-box in offline mode. If no AI API key (Mistral) or local Ollama instance is configured, Sentinel still maps findings directly to established security remediation protocols based on industry standards:

| Vulnerability Type | CWE | Description | Standard Remediation Protocol |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Concatenating untrusted user inputs directly into SQL query strings. | Use parameterized queries (prepared statements) e.g., `execute("SELECT * FROM users WHERE id = ?", (user_id,))` or ORMs. Never format/interpolate SQL strings. |
| **Cross-Site Scripting (XSS)** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Rendering untrusted user inputs in HTML templates or outputs without escaping. | Remove dangerous raw render calls (`|safe` filter, `mark_safe()`). Ensure auto-escaping is active and escape content with functions like `html.escape()`. |
| **Command Injection** | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Executing OS commands via subprocess calls with dynamic strings and `shell=True`. | Disable shell execution (`shell=False`). Pass command strings as sequences of args e.g., `subprocess.run(["ls", "-la"])` to prevent shell parser manipulation. |
| **Hardcoded Secrets** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Storing passwords, API tokens, keys, and private credentials directly inside source code. | Move all configuration and credentials to environment variables loaded via `.env` (e.g., `os.getenv("DB_PASS")`). Always add `.env` to `.gitignore`. |
| **Insecure Cryptography** | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | Utilizing weak or deprecated hashing algorithms (like MD5 or SHA-1) and weak ciphers. | Upgrade cryptosystems to strong alternatives (e.g., `hashlib.sha256` or `hashlib.sha3_256` for hashes, and `AES-GCM` for symmetric encryption). |
| **Outdated Dependencies** | [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Importing packages containing known CVEs published in OSV.dev and NVD databases. | Pin safe dependencies in lockfiles (`poetry.lock`, `uv.lock`, `package-lock.json`) and run package upgrade managers (e.g. `pip install --upgrade`). |

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
| **Publish to PyPI** | [pypi-publish.yml](.github/workflows/pypi-publish.yml) | Push tag `v*.*.*` | Runs quality checks first. If successful, builds wheels and publishes the distribution packages to [...]
| **Build & Publish Docker** | [docker-build.yml](.github/workflows/docker-build.yml) | Push to `main`, tags `v*`, or PyPI success | Automates building the optimized multi-stage Python wheel Docker im[...]
| **Deploy Docs** | [docs.yml](.github/workflows/docs.yml) | Push to `main` | Deploys static files from the `website/` folder directly to GitHub Pages at [https://ronaldgosso.github.io/sentinel](https://ronaldgosso.github.io/sentinel) [...]

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

---

## Community & Socials

Spread the word and share your journey with **Sentinel** using these engaging hashtags across GitHub, Twitter/X, and LinkedIn:

* **Global Tech & AppSec**: `#Cybersecurity` `#AppSec` `#DevSecOps` `#PythonSecurity` `#AISecurity` `#OpenSource` `#StaticAnalysis`
* **Tanzania & Africa Tech**: `#TanzaniaTech` `#SiliconDar` `#TechInTanzania` `#TanzaniaDevelopers` `#CodingInTanzania` `#AfricaTech`
