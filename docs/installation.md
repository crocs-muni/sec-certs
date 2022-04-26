# Installation

The tool can be pulled as a docker image with

```bash
docker pull seccerts/sec-certs
```

Alternatively, it can be installed from PyPi with

```bash
pip install -U sec-certs
```

Note, however, that `Python>=3.8` is required and there are some additional dependencies (see below) that are not shipped with the binary distribution.

The stable release is also published on [GitHub](https://github.com/crocs-muni/sec-certs/releases) from where it can be setup for development with

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Alternatively, our Our [Dockerfile](https://github.com/crocs-muni/sec-certs/blob/main/docker/Dockerfile) represents a reproducible way of setting up the environment.

## Dependencies

- [Java](https://www.java.com/en) is needed to parse tables in FIPS pdf documents, must be available from `PATH`.
- Some imported libraries have non-trivial dependencies to resolve:
    - [pdftotext](https://github.com/jalan/pdftotext) requires [Poppler](https://poppler.freedesktop.org/) to be installed. We've experienced issues with older versions of Poppler (`0.x`), make sure to install `20.x` version of these libraries.
    - [graphviz](https://pypi.org/project/graphviz/) requires `graphviz` to be on the path