# Multi-stage build
FROM python:3.10-slim AS builder

WORKDIR /build

# Install build tools
RUN pip install --no-cache-dir build

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY rules/ ./rules/

# Build the wheel
RUN python -m build --wheel

# Final image
FROM python:3.10-slim

WORKDIR /app

# Install the built wheel
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Copy rules since they might be needed outside the package
COPY --from=builder /build/rules /app/rules

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
