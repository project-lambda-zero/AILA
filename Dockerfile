# AILA backend + worker container.
#
# Multi-stage build:
#   1. base    — Python 3.12-slim with system libs the runtime needs
#                (libmagic for python-magic, libpq for psycopg, build
#                tools for native wheel fallbacks).
#   2. deps    — installs the package into a venv so the final stage
#                can copy a clean tree without keeping the build chain.
#   3. runtime — minimal image with the venv + source. ENTRYPOINT is
#                aila's typer CLI; CMD is the API server. Override CMD
#                to run a worker (e.g. ``CMD ["worker","-q","vr"]``).
#
# Build:
#   docker build -t aila:7.0.0 .
# Run API:
#   docker run -p 8000:8000 --env-file .env aila:7.0.0
# Run worker (override CMD):
#   docker run --env-file .env aila:7.0.0 worker -q vr
#
# This image does NOT bundle the frontend — the frontend is a separate
# Vite build served as static assets (use the dedicated frontend
# Dockerfile under frontend/ or serve via a CDN). The API container
# only serves the FastAPI app + workers.

# ── Stage 1: base system ────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System packages:
#   libmagic1   — python-magic file-type detection
#   libpq5      — psycopg connection layer
#   curl, ca-certificates — runtime HTTP + TLS
#   build-essential, libpq-dev, libffi-dev — for native wheel fallbacks
#                                            (cryptography, argon2-cffi)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmagic1 \
        libpq5 \
        curl \
        ca-certificates \
        build-essential \
        libpq-dev \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 2: install dependencies into venv ────────────────────────
FROM base AS deps

WORKDIR /build

# Copy only manifests first so dep changes don't bust the source layer.
COPY pyproject.toml README.md ./
COPY src/aila/__init__.py src/aila/__init__.py

# Create a venv so the final stage can copy /opt/venv only — no build
# artifacts, no pip cache, no setuptools history.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip wheel setuptools

# Install the package + its dependencies. Editable install would
# require the full source; we install non-editable so the venv is
# fully self-contained.
COPY src/ src/
RUN /opt/venv/bin/pip install ".[server]"

# ── Stage 3: minimal runtime ───────────────────────────────────────
FROM base AS runtime

# Copy the populated venv from the deps stage.
COPY --from=deps /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Source tree — needed because alembic migrations + module entry
# points are loaded by path at startup. Keep ownership simple
# (root) since the container should run as a non-root user via the
# orchestrator's UID/GID mapping in production, not baked into the
# image (different orchestrators want different UIDs).
WORKDIR /app
COPY src/ ./src/
COPY pyproject.toml README.md ./
COPY scripts/ ./scripts/
COPY infra/ ./infra/

# AILA reads PYTHONPATH-aware imports from /app/src.
ENV PYTHONPATH=/app/src

# Default port for the FastAPI app. Override via -p / -P at run time.
EXPOSE 8000

# Healthcheck hits /health. The endpoint returns 200 even when
# downstream subsystems are degraded — that's the right answer for
# k8s liveness (the container itself is alive). Readiness probes
# should check /health AND parse the JSON body to gate traffic.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

# ENTRYPOINT is the aila CLI so CMD can be a sub-command. Override
# CMD to run a worker:
#   CMD ["worker", "-q", "vr"]
ENTRYPOINT ["aila"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
