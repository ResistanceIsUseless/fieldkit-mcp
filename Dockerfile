# Multi-stage build for smaller image
FROM golang:1.24-alpine AS go-builder

# Install Go-based tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Python base image
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Go binaries from builder stage
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/
COPY --from=go-builder /go/bin/dnsx /usr/local/bin/
COPY --from=go-builder /go/bin/katana /usr/local/bin/

# Verify Go tools are executable
RUN chmod +x /usr/local/bin/*

# Install theHarvester (Python-based)
RUN pip install --no-cache-dir theHarvester

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY recon_mcp_server.py .

# Create non-root user for security
RUN useradd -m -u 1000 mcpuser && chown -R mcpuser:mcpuser /app
USER mcpuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/mcp || exit 1

# Default environment variables
ENV RECON_MCP_PORT=8000

# Default command
CMD ["python", "recon_mcp_server.py"]