# CI/CD Integration

## GitHub Action

Add a workflow file `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ronaldgosso/sentinel-action@v1
        with:
          api-key: ${{ secrets.MISTRAL_API_KEY }}
          fail-on: high
          upload-sarif: true
```

## Docker

```bash
docker run ghcr.io/ronaldgosso/sentinel:latest scan . --ci
```

## GitLab CI

```yaml
security-scan:
  image: ghcr.io/ronaldgosso/sentinel:latest
  script:
    - sentinel scan . --ci
```

## Jenkins

Add a stage that runs `sentinel scan . --ci` inside a Python environment.
