# Installation

::::{tab-set}
:::{tab-item} PyPi (pip)

The tool can be installed from PyPi with

```bash
pip install -U sec-certs && python -m spacy download en_core_web_sm
```

Note, that `Python>=3.10` is required.

:::

:::{tab-item} Docker

The tool can be pulled as a docker image with

```bash
docker pull seccerts/sec-certs
```

:::
:::{tab-item} Build from sources

The stable release is also published on [GitHub](https://github.com/crocs-muni/sec-certs/releases) from where it can be setup for development with

```bash
git clone https://github.com/crocs-muni/sec-certs.git
python3 -m venv venv
source venv/bin/activate
pip install -e .
python -m spacy download en_core_web_sm
```

Alternatively, our [Dockerfile](https://github.com/crocs-muni/sec-certs/blob/main/Dockerfile) represents a reproducible way of setting up the environment.

:::
::::

If you're not using Docker, you must install the dependencies as described below.

## Dependencies

- [Java](https://www.java.com/en) is needed to parse tables in FIPS pdf documents, must be available from `PATH`.
- Some imported libraries have non-trivial dependencies to resolve:
    - [pdftotext](https://github.com/jalan/pdftotext) requires [Poppler](https://poppler.freedesktop.org/) to be installed. We've experienced issues with older versions of Poppler (`0.x`), make sure to install `20.x` version of these libraries.
    - [tesseract](https://github.com/tesseract-ocr/tesseract) is required for OCR of malformed PDF documents, together with data files for English, French and German.
