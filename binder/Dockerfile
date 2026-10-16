# Binder image: the released sec-certs image + Jupyter + the repository contents.
#
# repo2docker uses this file because a binder/ folder exists (root config is ignored).
# Build context is the repository root, so COPY paths are relative to the root
# and the root .dockerignore applies here too.
#
# Everything sec-certs needs at runtime (system packages, Python, compiled pdftotext,
# spaCy model, user "user" with UID 1000) comes from the released image, so this file
# only adds what Binder needs on top.

# uv is used only during the build (mounted, not copied), so it does not end up in the image.
FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

# TODO: replace with the first release built from the new root Dockerfile.
# Dependabot (docker ecosystem, directory /binder) keeps this pin up to date afterwards.
FROM seccerts/sec-certs:<VERSION>@sha256:<DIGEST> AS binder

USER root

# Jupyter Notebook and JupyterLab with versions from the "binder" dependency group in uv.lock.
# The group is exported from the lock file at build time (no second, hand-maintained
# requirements file) and installed with hashes into the existing venv.
# --frozen: use uv.lock as-is; the root Dockerfile already checks it with --locked.
# --no-deps: install exactly the exported set, no new resolution.
RUN --mount=from=uv,source=/uv,target=/bin/uv \
    --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=pyproject.toml,target=/tmp/lock/pyproject.toml \
    --mount=type=bind,source=uv.lock,target=/tmp/lock/uv.lock \
    UV_LINK_MODE=copy uv export \
        --project /tmp/lock --frozen --only-group binder --no-emit-project \
        --format requirements.txt --output-file /tmp/jupyter.txt \
    && UV_LINK_MODE=copy uv pip install \
        --python /app/.venv/bin/python --require-hashes --no-deps --compile-bytecode \
        -r /tmp/jupyter.txt \
    && rm /tmp/jupyter.txt

# Binder requires the repository contents in $HOME, owned by the user,
# so that notebooks/... resolves from the documentation links.
COPY --chown=user:user . /home/user

USER user
WORKDIR /home/user

# No ENTRYPOINT: Binder starts the container with its own command.
# (The old ENTRYPOINT ["sec-certs"] swallowed that command, so Jupyter never started.)
# CMD is only for local use: docker run --rm -p 8888:8888 <image>
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--no-browser"]