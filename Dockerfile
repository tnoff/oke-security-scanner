FROM python:3.13-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    tar \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy from GitHub releases
ARG TRIVY_VERSION=v0.61.1
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh |  sh -s -- -b /usr/local/bin ${TRIVY_VERSION}

# Pre-download Trivy vulnerability database
RUN trivy image --download-db-only

# Set up Python environment
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/

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
