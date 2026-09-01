# Sentinel Docker Image

The Sentinel Docker image provides a portable and isolated environment to run security scans on your projects (supporting Python, JavaScript/TypeScript, HTML, CSS, and dependencies) without installing dependencies on your host machine.

## Usage

You can run Sentinel using Docker by mounting your project directory into the container.

```bash
docker run --rm -v $(pwd):/app ghcr.io/ronaldgosso/sentinel:latest scan .
```

### AI Assistance (Dual-Tier Access & Rate Limiting)

Sentinel includes **built-in AI assistance** by default (rate-limited to 1.0 req/s with automatic retry backoff).

To use your own Mistral AI key for **unrestricted speed**:

```bash
docker run --rm \
  -v $(pwd):/app \
  -e MISTRAL_API_KEY="your-api-key" \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai
```

You can also customize the client rate limit via `--ai-rate-limit`:
```bash
docker run --rm \
  -v $(pwd):/app \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai-rate-limit 2.0
```

### Exporting Reports

Sentinel supports exporting findings in **JSON**, **SARIF**, **HTML**, and **Markdown** (for GitHub Action PR summaries and comments).

```bash
# Export Markdown report
docker run --rm \
  -v $(pwd):/app \
  ghcr.io/ronaldgosso/sentinel:latest scan . --output-format markdown --output-file /app/sentinel-report.md

# Export SARIF for GitHub Code Scanning
docker run --rm \
  -v $(pwd):/app \
  ghcr.io/ronaldgosso/sentinel:latest scan . --output-format sarif --output-file /app/sentinel-report.sarif
```

## Image Details

- **Base Image**: python:3.10-slim
- **Working Directory**: /app
- **Default Entrypoint**: The container automatically delegates commands to the sentinel CLI. If no command is provided, it defaults to scan.
