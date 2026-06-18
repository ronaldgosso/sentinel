# Contributing to Sentinel

Thank you for your interest in contributing to Sentinel! We welcome bug reports, feature requests, and pull requests from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Adding New Rules](#adding-new-rules)
- [Submitting Pull Requests](#submitting-pull-requests)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone. 

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a new branch for your feature or bugfix.

## Development Environment

We recommend using a virtual environment (e.g., venv or conda). 

```bash
git clone https://github.com/ronaldgosso/sentinel.git
cd sentinel
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

Ensure you run tests and linters before submitting code:

```bash
pytest
ruff check src/
mypy src/
```

## Adding New Rules

Sentinel uses YAML-based rules for SAST scanning. You can add new rules in the rules/sast/ directory. Each rule must define an ID, a description, a severity level, and a regular expression pattern to match vulnerable code.

## Submitting Pull Requests

1. Commit your changes with clear, descriptive commit messages.
2. Push your branch to your fork.
3. Open a Pull Request against the main branch.
4. Ensure all CI checks pass.
