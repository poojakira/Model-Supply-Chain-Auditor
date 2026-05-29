FROM python:3.12-slim AS base

WORKDIR /app

# Copy project files
COPY pyproject.toml requirements.txt rules.yaml ./
COPY src/ src/
COPY tests/ tests/

# Install with non-root user context
RUN pip install --no-cache-dir -e .

# Create non-root user for runtime
FROM base AS runtime

RUN useradd -m -u 1000 -s /sbin/nologin scanner && \
    chown -R scanner:scanner /app

USER scanner

# Health check: verify scanner CLI works
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD msca --help > /dev/null 2>&1 || exit 1

ENTRYPOINT ["msca"]
CMD ["--help"]
