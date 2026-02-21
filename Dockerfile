FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency installation
RUN pip install --no-cache-dir uv

# Copy dependency manifest first for layer caching
COPY pyproject.toml .

# Install production dependencies only (no dev extras)
RUN uv pip install --system --no-cache .

# Copy application source
COPY app/ app/

# Non-root user for PCI compliance
RUN adduser --disabled-password --no-create-home --gecos "" appuser
USER appuser

EXPOSE 8080

# 4 uvicorn workers; adjust via CMD override for different instance sizes
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4", "--log-level", "warning"]
