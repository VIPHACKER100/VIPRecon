# VIPRecon Docker Image
# Professional Web Application Reconnaissance and Security Testing Tool
# Version: 1.1.0

FROM python:3.13-slim

LABEL maintainer="viphacker100 (Aryan Ahirwar) <viphacker.100.org@gmail.com>"
LABEL description="VIPRecon - Web Application Reconnaissance and Security Testing Tool"
LABEL version="1.1.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory
RUN mkdir -p /app/output

# Create a non-root user for security
RUN useradd -m -u 1000 viprecon && \
    chown -R viprecon:viprecon /app
USER viprecon

# Set entrypoint
ENTRYPOINT ["python", "main.py"]

# Default command (show help)
CMD ["--help"]
