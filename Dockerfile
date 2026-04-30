FROM python:3.14-slim

# Install system dependencies
# Update packages for security updates
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    tar \
    curl \
    git \
    && apt-get -y upgrade \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy from GitHub releases
ARG TRIVY_VERSION=v0.70.0
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh |  sh -s -- -b /usr/local/bin ${TRIVY_VERSION}

# Pre-download Trivy vulnerability database
RUN trivy image --download-db-only

# Set up Python environment
WORKDIR /app

# Copy pyproject and install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code
COPY src/ ./src/

# Uninstall some previous packages
RUN apt-get remove -y git && apt-get autoremove -y

# Run as non-root user
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app && \
    mkdir -p /home/scanner/.cache/trivy && \
    chown -R scanner:scanner /home/scanner/.cache

USER scanner

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy

CMD ["python", "-m", "src.main"]
