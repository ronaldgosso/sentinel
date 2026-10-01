# Sentinel Docker Image

The Sentinel Docker image provides a portable and isolated environment to run security scans on your projects (supporting Python, JavaScript/TypeScript, HTML, CSS, and dependencies) without installing dependencies on your host machine.

## Usage

You can run Sentinel using Docker by mounting your project directory into the container.

```bash
docker run --rm -v $(pwd):/app ghcr.io/ronaldgosso/sentinel:latest scan .
```

### AI Assistance (Multi-Vendor: Mistral, OpenAI, Anthropic, Gemini, Groq, Ollama)

To enable AI enrichment and automated explanations, specify your preferred vendor and pass credentials via environment variables or CLI options:

**OpenAI:**
```bash
docker run --rm \
  -v $(pwd):/app \
  -e OPENAI_API_KEY="sk-..." \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai-vendor openai
```

**Anthropic Claude:**
```bash
docker run --rm \
  -v $(pwd):/app \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai-vendor anthropic
```

**Mistral AI:**
```bash
docker run --rm \
  -v $(pwd):/app \
  -e MISTRAL_API_KEY="your-api-key" \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai-vendor mistral
```

**Or pass API keys directly via CLI arguments:**
```bash
docker run --rm \
  -v $(pwd):/app \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai-vendor openai --ai-api-key "sk-..."
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
