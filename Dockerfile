# Multi-stage build
FROM python:3.10-slim AS builder

WORKDIR /build

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --user .

# Copy source
COPY src/ /build/src/
COPY rules/ /build/rules/
COPY .sentinel.yml* /build/

# Build the package
RUN pip install --no-cache-dir --user .

# Final image
FROM python:3.10-slim

# Copy installed package from builder
COPY --from=builder /root/.local /root/.local
COPY --from=builder /build/rules /app/rules

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

WORKDIR /app

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
