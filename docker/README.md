# Sentinel Docker Image

The Sentinel Docker image provides a portable and isolated environment to run security scans on your Python projects without installing dependencies on your host machine.

## Usage

You can run Sentinel using Docker by mounting your project directory into the container.

```bash
docker run --rm -v $(pwd):/app ghcr.io/ronaldgosso/sentinel:latest scan .
```

### Passing Environment Variables

To enable the Mistral AI backend for intelligent auto-fixes, pass your API key as an environment variable:

```bash
docker run --rm \
  -v $(pwd):/app \
  -e MISTRAL_API_KEY="your-api-key" \
  ghcr.io/ronaldgosso/sentinel:latest scan . --ai
```

### Exporting Reports

If you specify an output file for reports, the file will be saved in your mounted workspace directory.

```bash
docker run --rm \
  -v $(pwd):/app \
  ghcr.io/ronaldgosso/sentinel:latest scan . --output-format sarif --output-file /app/sentinel-report.sarif
```

## Image Details

- **Base Image**: python:3.10-slim
- **Working Directory**: /app
- **Default Entrypoint**: The container automatically delegates commands to the sentinel CLI. If no command is provided, it defaults to scan.
