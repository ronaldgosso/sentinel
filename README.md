# Sentinel

AI-powered security hardening for Python projects. Sentinel performs SAST, SCA, and DAST scanning, and uses AI to provide actionable auto-fixes.

## Installation

```bash
pip install sentinel
```

## GitHub Action

Sentinel is available as a GitHub Action to seamlessly integrate into your CI/CD pipelines. It supports outputting SARIF reports that integrate directly with GitHub Code Scanning.

### Example Usage

Create `.github/workflows/security.yml` in your repository:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Sentinel scan
        uses: ronaldgosso/sentinel@v1
        with:
          api-key: ${{ secrets.MISTRAL_API_KEY }}
          fail-on: high
          upload-sarif: true
          # Optional: enable DAST
          # dast-url: http://localhost:8000
```