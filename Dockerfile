# ---- Builder Stage ----
FROM python:3.12-slim-bookworm AS builder

# Install uv by copying the binary from the official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a virtual environment
RUN uv venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
# Add the venv to the PATH
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy dependency definitions
COPY pyproject.toml uv.lock README.md ./

# Install production dependencies (excluding dev dependencies) into the venv
# Use --frozen to ensure uv.lock is used and up-to-date
# Use --no-editable as we copy the final venv, not source links
RUN uv sync --frozen --no-dev --no-editable

# Copy the application source code
COPY ./template_python_vsa ./template_python_vsa

# ---- Final Stage ----
FROM python:3.12-slim-bookworm AS final

# Create a non-root user and group
RUN groupadd --system --gid 1001 appgroup && useradd --system --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy the virtual environment with dependencies from the builder stage
COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv
# Copy the application code from the builder stage
COPY --from=builder --chown=appuser:appgroup /app/template_python_vsa ./template_python_vsa

# Switch to the non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 8000

# Set the command to run the application
CMD ["uvicorn", "template_python_vsa.main:app", "--host", "0.0.0.0", "--port", "8000"] 