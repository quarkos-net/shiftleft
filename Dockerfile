# Reproducible Environment for Paper Verification
#
# This Dockerfile creates a deterministic environment for reproducing
# all experiments from:
# "Pre-Silicon Side-Channel Verification of Post-Quantum Hardware"
#
# LEGAL EVIDENCE: This image hash proves the exact environment used.
#
# Build:   docker build -t shiftleft-reproducible .
# Run:     docker run --rm shiftleft-reproducible python scripts/reproduce_paper.py
# Hash:    docker inspect --format='{{.Id}}' shiftleft-reproducible

FROM python:3.11.7-slim-bookworm

LABEL maintainer="Ray Iskander"
LABEL description="Reproducible environment for PQC side-channel verification paper"
LABEL version="1.0"
LABEL paper="Pre-Silicon Side-Channel Verification of Post-Quantum Hardware"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements first (for layer caching)
COPY requirements.txt requirements-reproducibility.txt ./

# Install Python dependencies with EXACT versions for reproducibility
RUN pip install --no-cache-dir \
    z3-solver==4.12.4.0 \
    PyYAML==6.0.1 \
    pydantic==2.5.3 \
    pydantic-settings==2.1.0 \
    pytest==7.4.4 \
    pytest-asyncio==0.23.3

# Record installed versions
RUN pip freeze > /app/installed_versions.txt

# Copy source code
COPY src/ src/
COPY scripts/ scripts/
COPY tests/ tests/

# Clone external targets at specific commits
RUN mkdir -p external && \
    git clone https://github.com/chipsalliance/adams-bridge external/adams-bridge && \
    cd external/adams-bridge && git checkout f92a363 && cd ../.. && \
    git clone --depth 1 https://github.com/lowrisc/opentitan external/opentitan

# Set PYTHONPATH
ENV PYTHONPATH=/app/src:$PYTHONPATH

# Verify installation
RUN python -c "import z3; print(f'Z3 version: {z3.get_version_string()}')"
RUN python -c "import sys; print(f'Python version: {sys.version}')"

# Default command: run reproduction script
CMD ["python", "scripts/reproduce_paper.py"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import z3; import yaml; print('OK')" || exit 1
