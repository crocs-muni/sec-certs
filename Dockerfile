# syntax=docker/dockerfile:1
# Targets:
#   docker buildx build .                   -> slim image (default, last stage)
#   docker buildx build --target jupyter .  -> slim + Jupyter + notebooks
# Stage graph:
#   deps ──┬──> builder ─────────────────────────> slim
#          └──> deps-jupyter ──> builder-jupyter ─> jupyter
#   runtime is the common base of slim and jupyter; each gets its own venv.
# uv in its own stage: Dependabot tracks images in FROM lines, not in COPY --from
FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

# ---------- deps ----------
# Everything that does not depend on the source code, so code changes reuse it from cache.
FROM ubuntu:noble@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS deps

ARG DEBIAN_FRONTEND=noninteractive

# Needed to compile pdftotext (no prebuilt wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpoppler-cpp-dev \
    python3-dev \
    python3.12 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /bin/

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
ENV UV_NO_DEV=1
ENV UV_PYTHON_DOWNLOADS=0
ENV UV_PYTHON=/usr/bin/python3.12

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# spaCy model is not on PyPI: fixed version, verified by checksum
ADD --checksum=sha256:1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85 https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl /tmp/
RUN uv pip install --python /app/.venv/bin/python --no-deps /tmp/en_core_web_sm-3.8.0-py3-none-any.whl

# ---------- deps-jupyter ----------
# --inexact keeps the spaCy model, which is not in uv.lock
FROM deps AS deps-jupyter
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --inexact --group jupyter

# ---------- builder ----------
# Version comes from a build arg (.git is not in the context); release.yml passes the tag.
# --reinstall-package: otherwise uv reuses a cached wheel with old code or an old version.
FROM deps AS builder
COPY . /app
ARG SETUPTOOLS_SCM_PRETEND_VERSION_FOR_SEC_CERTS=0.0.0+local
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --inexact --reinstall-package sec-certs

# ---------- builder-jupyter ----------
# Same as builder; --group jupyter keeps the Jupyter packages
FROM deps-jupyter AS builder-jupyter
COPY . /app
ARG SETUPTOOLS_SCM_PRETEND_VERSION_FOR_SEC_CERTS=0.0.0+local
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable --inexact --group jupyter --reinstall-package sec-certs

# ---------- runtime ----------
# Common base of the final stages: no compilers, no uv
FROM ubuntu:noble@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-jre-headless \
    libpoppler-cpp0t64 \
    poppler-utils \
    python3.12 \
    tesseract-ocr tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-fra \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

# UID 1000 (taken by "ubuntu") matches the usual host user; home 755 so other UIDs can reach mounts
RUN userdel --remove ubuntu \
    && useradd --create-home --uid 1000 --shell /bin/bash user \
    && chmod 755 /home/user

WORKDIR /home/user

# ---------- jupyter ----------
FROM runtime AS jupyter

COPY --from=builder-jupyter --chown=user:user /app/.venv /app/.venv
COPY --chown=user:user notebooks /home/user/notebooks

USER user
EXPOSE 8888
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--no-browser"]

# ---------- slim (default, must stay last) ----------
FROM runtime AS slim

COPY --from=builder /app/.venv /app/.venv

USER user
CMD ["/bin/bash"]