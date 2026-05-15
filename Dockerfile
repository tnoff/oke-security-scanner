FROM python:3.14-slim AS trivy-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG TRIVY_VERSION=v0.70.0
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
    sh -s -- -b /usr/local/bin ${TRIVY_VERSION}


FROM python:3.14-slim

# Apply security upgrades only; no build tools needed in the final image.
RUN apt-get update && \
    apt-get -y upgrade && \
    rm -rf /var/lib/apt/lists/*

# Copy the trivy binary from the builder stage
COPY --from=trivy-builder /usr/local/bin/trivy /usr/local/bin/trivy

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY src/ ./src/

# Run as non-root user
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app && \
    mkdir -p /home/scanner/.cache/trivy && \
    chown -R scanner:scanner /home/scanner/.cache

USER scanner

ENV PYTHONUNBUFFERED=1
ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy

CMD ["python", "-m", "src.main"]
