FROM python:3.14-slim AS trivy-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ARG TRIVY_VERSION=v0.70.0
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
    sh -s -- -b /usr/local/bin ${TRIVY_VERSION}


# Compiles Python deps that don't ship aarch64 wheels for the runtime Python
# (e.g. crc32c, a transitive dep of oci 2.178+). build-essential stays here;
# the runtime stage copies only the installed packages out of /install.
FROM python:3.14-slim AS py-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.14-slim

# Apply security upgrades only; no build tools needed in the final image.
RUN apt-get update && \
    apt-get -y upgrade && \
    rm -rf /var/lib/apt/lists/*

# Copy the trivy binary from the builder stage
COPY --from=trivy-builder /usr/local/bin/trivy /usr/local/bin/trivy

# Copy Python deps installed in the py-builder stage
COPY --from=py-builder /install /usr/local

WORKDIR /app

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
