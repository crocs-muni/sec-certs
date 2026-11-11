# Installation

::::{tab-set}
:::{tab-item} PyPI

sec-certs requires Python 3.10+ and is published on [PyPI](https://pypi.org/project/sec-certs/), so you can install it with any Python package manager, e.g.:

```bash
pip install -U sec-certs   # pip
uv add sec-certs           # uv, in a uv project
```

Before installing, set up the [dependencies](#dependencies) below: one of the Python dependencies (`pdftotext`) is compiled during installation.

To convert PDFs with [Docling](https://github.com/docling-project/docling) instead of pdftotext, install the `docling` extra (`sec-certs[docling]`).

:::

:::{tab-item} Docker

The Docker images come with all dependencies set up. They are published on [Docker Hub](https://hub.docker.com/r/seccerts/sec-certs) in three variants:

- `seccerts/sec-certs` (tags `latest`, `<version>`): the `sec-certs` CLI and library.
- `seccerts/sec-certs:latest-jupyter` (tags `latest-jupyter`, `<version>-jupyter`): the same, plus JupyterLab and the example notebooks.
- `seccerts/sec-certs:latest-docling` (tags `latest-docling`, `<version>-docling`): converts PDFs with Docling instead of pdftotext, with its models included. It's much larger (about 12 GB), mostly because of PyTorch with CUDA.

```bash
docker pull seccerts/sec-certs
```

See [Run sec-certs from Docker](quickstart.md#run-sec-certs-from-docker) for how to use them.

:::

:::{tab-item} From source

For development, clone the repository and install it with [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/crocs-muni/sec-certs.git
cd sec-certs
uv sync --inexact
```

Add `--extra docling` for Docling. See [contributing](contributing.md) for more about the development setup.

You can also build the Docker images yourself:

```bash
docker build -t sec-certs .                            # CLI and library
docker build --target jupyter -t sec-certs-jupyter .   # plus JupyterLab and the example notebooks
docker build --target docling -t sec-certs-docling .   # with Docling and its models
```

Locally built images report the version `0.0.0+local`. To set a real one, add `--build-arg SETUPTOOLS_SCM_PRETEND_VERSION_FOR_SEC_CERTS=<version>`.

:::
::::

## Dependencies

These are not needed with Docker.

- [Poppler](https://poppler.freedesktop.org/) 20.x or newer and a C++ compiler: `pdftotext` is compiled against Poppler during installation and uses it to convert PDFs.
- [Tesseract](https://github.com/tesseract-ocr/tesseract) with data files for English, German and French: OCR of PDFs that pdftotext can't read.
- [Java](https://www.java.com/en), available from `PATH`: parsing tables in PDF documents.

For example:

::::{tab-set}
:::{tab-item} Ubuntu / Debian

```bash
sudo apt-get install build-essential pkg-config python3-dev libpoppler-cpp-dev poppler-utils \
    tesseract-ocr tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-fra default-jre
```

:::
:::{tab-item} macOS (Homebrew)

```bash
brew install pkg-config poppler tesseract tesseract-lang
brew install --cask temurin   # Java
```

:::
::::
