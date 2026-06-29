# Comlink — read-only Proton Mail MCP server, containerized for K3s on Gonk.
#
# Multi-stage, uv-based, non-root. Stage 1 resolves the frozen dependency graph
# from uv.lock into a self-contained /app/.venv; stage 2 is a slim runtime that
# carries only the venv + source (no uv, no build toolchain, no dev deps).
#
# NOTE: This image was NOT build-tested in the authoring environment (no usable
# docker build there). Build it on Gonk per deploy/README.md and treat the first
# build as the smoke test.

# ---- Stage 1: builder -------------------------------------------------------
# uv's official image with Python 3.12 baked in (bookworm-slim base, matching
# stage 2's python:3.12-slim-bookworm so the resolved interpreter is identical).
# This tag tracks the latest uv — a build tool whose exact version isn't
# runtime-critical; pin to a specific uv release (e.g. :0.5.x-python3.12-...) if
# you want fully reproducible builds.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

# uv build-time behavior:
#   - compile bytecode for faster cold starts
#   - copy (not symlink) packages so the venv is self-contained for stage 2
#   - never try to manage/download a different Python; use the base image's
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Layer 1: dependencies only. Copy just the lock + manifest so this layer is
# cached across source-only changes. --no-install-project installs deps but not
# comlink itself; --no-dev excludes the pytest/ruff/mypy group.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Layer 2: the project source, then install the project (the `comlink` script).
COPY src ./src
COPY README.md ./README.md
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---- Stage 2: runtime -------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# Non-root runtime user (fixed UID/GID so the K8s securityContext can pin it).
# 65532 is the conventional "nonroot" UID (matches distroless), unprivileged.
RUN groupadd --gid 65532 comlink \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /app comlink

WORKDIR /app

# Carry over only the resolved venv and the source. No uv, no caches, no dev deps.
COPY --from=builder --chown=65532:65532 /app/.venv /app/.venv
COPY --from=builder --chown=65532:65532 /app/src /app/src

# Put the venv on PATH so the `comlink` console script is the entrypoint.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Transport defaults baked into the image (overridable by the Deployment env).
# Bind all interfaces inside the container; the Service/tunnel front it.
# NO secrets, NO credentials, NO Bridge host/cert paths baked in — those come
# from the Deployment env, the Secret, and the mounted ConfigMap at runtime.
ENV COMLINK_TRANSPORT=streamable-http \
    COMLINK_HTTP_HOST=0.0.0.0 \
    COMLINK_HTTP_PORT=8000

EXPOSE 8000

USER 65532:65532

# The console script defined in pyproject.toml: comlink = comlink.server:main
ENTRYPOINT ["comlink"]
