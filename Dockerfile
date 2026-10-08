# uv in its own stage: Dependabot tracks images in FROM lines (not in COPY --from), so uv can be updated automatically
FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

# ---------- builder ----------
# Compilers and -dev headers live only here (needed to build pdftotext).
# Only /app/.venv is copied to the runtime stage.
FROM ubuntu:noble@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS builder

ARG DEBIAN_FRONTEND=noninteractive

# pdftotext publishes no prebuilt wheels and is compiled from source, which needs:
# a C++ compiler (build-essential), Python headers (python3-dev), poppler headers (libpoppler-cpp-dev).
RUN apt-get update && apt-get install -y --no-install-recommends \
 build-essential \
 libpoppler-cpp-dev \
 python3-dev \
 python3.12 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /bin/

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
ENV UV_NO_DEV=1

# Use the system Python from Ubuntu; the venv must point to the same path in runtime
ENV UV_PYTHON_DOWNLOADS=0
ENV UV_PYTHON=/usr/bin/python3.12

WORKDIR /app

# Install dependencies before copying the source code: this slow step is
# reused from cache on code changes and reruns only when uv.lock or pyproject.toml change.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project
COPY . /app

# No .git in the image: the version is passed as a build argument
ARG SETUPTOOLS_SCM_PRETEND_VERSION_FOR_SEC_CERTS

# --no-editable installs sec-certs into the venv itself, not as a link to /app/src.
# Only the venv is copied to the runtime stage, so it must not depend on /app.
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-editable

# The spaCy model is not on PyPI, so uv sync does not install it.
# Instead of `spacy download` (latest version, no verification), a fixed wheel is
# downloaded and verified by checksum. Version 3.8.0 matches spaCy 3.8 (compatibility.json).
ADD --checksum=sha256:1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85 https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl /tmp/
RUN uv pip install --python /app/.venv/bin/python --no-deps /tmp/en_core_web_sm-3.8.0-py3-none-any.whl


# ---------- runtime ----------
# Only packages needed to run sec-certs; no compilers, no uv.
FROM ubuntu:noble@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

# libpoppler-cpp0t64: runtime library of the compiled pdftotext extension
RUN apt-get update && apt-get install -y --no-install-recommends \
 default-jre-headless \
 libpoppler-cpp0t64 \
 poppler-utils \
 python3.12 \
 qpdf \
 tesseract-ocr tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-fra \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1

# Non-root user "user" with UID 1000: the docs use /home/user, and UID 1000
# matches the usual host user, so bind-mounted host folders are writable.
# The base image already has user "ubuntu" with UID 1000, so it is removed first.
# Home is 755 (useradd default is 750) so that `docker run --user <other UID>`
# can still reach folders mounted under /home/user.
RUN userdel --remove ubuntu \
 && useradd --create-home --uid 1000 --shell /bin/bash user \
 && chmod 755 /home/user

COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

USER user
WORKDIR /home/user

# Default: a shell. Any command given to `docker run` replaces it,
# e.g. `docker run <image> sec-certs --help` or `docker run <image> python script.py`.
CMD ["/bin/bash"]
