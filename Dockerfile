# Multi-stage build for one-command setup
FROM golang:1.24-alpine AS go-builder

# Install build dependencies for CGO tools
RUN apk add --no-cache git gcc musl-dev

# ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# TruffleHog — secret scanner
RUN go install github.com/trufflesecurity/trufflehog/v3@latest

# Custom recon tools
RUN go install github.com/ResistanceIsUseless/webscope@latest
RUN go install github.com/ResistanceIsUseless/subscope@latest

# Runtime with Chromium + browser deps preinstalled
FROM mcr.microsoft.com/playwright/python:v1.47-jammy

# Install system dependencies (including nmap)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Go binaries from builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/
COPY --from=go-builder /go/bin/httpx /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/
COPY --from=go-builder /go/bin/trufflehog /usr/local/bin/
COPY --from=go-builder /go/bin/webscope /usr/local/bin/
COPY --from=go-builder /go/bin/subscope /usr/local/bin/

# Verify Go tools are executable
RUN chmod +x /usr/local/bin/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install theHarvester (Python-based)
RUN pip install --no-cache-dir theHarvester

# Clone SecLists for DNS bruteforce aliases
RUN mkdir -p /opt/wordlists && git clone --depth=1 https://github.com/danielmiessler/SecLists.git /opt/wordlists/SecLists

# Copy MCP server code
COPY fieldkit_mcp_server.py .
COPY recon_mcp_server.py .
COPY web_tools.py .
COPY cache.py .

# Data directories
RUN mkdir -p /app/cache /app/output

# Create non-root user for security
# Note: nmap requires elevated privileges for SYN/OS/UDP scans;
# run the container with --cap-add=NET_RAW if those scan types are needed.
RUN useradd -m -u 1000 mcpuser && chown -R mcpuser:mcpuser /app
USER mcpuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/mcp || exit 1

# Default environment variables
ENV FIELDKIT_MCP_PORT=8000
ENV WORDLIST_DIR=/opt/wordlists/SecLists
ENV CACHE_DB=/app/cache/cache.db

# Default command
CMD ["python", "fieldkit_mcp_server.py"]
