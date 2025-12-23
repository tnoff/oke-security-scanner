FROM python:3.14-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    tar \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy from GitHub releases
ARG TRIVY_VERSION=0.58.2
RUN wget -qO trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" && \
    tar -xzf trivy.tar.gz && \
    mv trivy /usr/local/bin/ && \
    rm trivy.tar.gz && \
    chmod +x /usr/local/bin/trivy

# Install kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && \
    mv kubectl /usr/local/bin/

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
