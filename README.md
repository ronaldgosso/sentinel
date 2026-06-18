# Sentinel

**Sentinel** is an AI-powered security hardening tool for Python developers. It provides seamless integration of Static Application Security Testing (SAST), Software Composition Analysis (SCA), and Dynamic Application Security Testing (DAST) with actionable, AI-driven auto-fixes.

[![PyPI version](https://badge.fury.io/py/sentinel-security.svg)](https://badge.fury.io/py/sentinel-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [GitHub Action](#github-action)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Overview

Sentinel scans your Python code for vulnerabilities, enriches the findings with context using the Mistral API (or local Ollama), and provides a terminal-based interactive dashboard to review and apply code fixes automatically.

## Features

- **SAST**: Scans source code for common anti-patterns using custom YAML rules.
- **SCA**: Audits project dependencies against the OSV database.
- **DAST**: Tests running web applications for dynamic vulnerabilities.
- **AI Enrichment**: Uses the Mistral API to analyze findings and suggest precise code fixes.
- **Auto-Fix**: Interactively or automatically apply fixes directly to your codebase.
- **Exporting**: Export scan results to JSON, HTML, or SARIF for CI/CD integration.
- **CLI Subcommands**: Clean and structured CLI experience (scan, init, update-db).

## Installation

You can install Sentinel directly from PyPI:

```bash
pip install sentinel-security
```

## Quick Start

Initialize Sentinel in your repository to create the default .sentinel.yml configuration:

```bash
sentinel init
```

Run a standard scan on your project:

```bash
sentinel scan .
```

To enable the AI integration, ensure your Mistral API key is available in your environment:

```bash
export MISTRAL_API_KEY="your-api-key-here"
sentinel scan . --ai
```

### Applying Fixes

You can automatically apply the AI-suggested fixes in interactive mode:

```bash
sentinel scan . --fix
```

## Configuration

The default .sentinel.yml configuration allows you to customize the scanning behavior, such as ignoring specific directories or defining custom severity thresholds. Run `sentinel init` to generate a template.

## GitHub Action

Sentinel is designed for seamless CI/CD integration. See the [Example Workflow](.github/example-workflow.yml) to integrate Sentinel into your GitHub Actions.

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) to get started with developing custom detectors or improving the core engine.

## Security

Please refer to our [Security Policy](SECURITY.md) for information on reporting vulnerabilities.

## License

This project is licensed under the MIT License.