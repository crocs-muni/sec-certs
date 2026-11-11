# Quickstart

::::{tab-set}

:::{tab-item} Common Criteria
1. Install sec-certs, e.g. with `pip install -U sec-certs` (see [installation](installation.md)).
2. In your Python interpreter, type
```python
from sec_certs.dataset.cc import CCDataset

dset = CCDataset.from_web()
```
to obtain the freshly processed dataset from [sec-certs.org](https://sec-certs.org).

3. Play with the dataset. See [example notebook](./notebooks/examples/cc.ipynb).
:::

:::{tab-item} FIPS 140
1. Install sec-certs, e.g. with `pip install -U sec-certs` (see [installation](installation.md)).
2. In your Python interpreter, type
```python
from sec_certs.dataset.fips import FIPSDataset

dset = FIPSDataset.from_web()
```
to obtain the freshly processed dataset from [sec-certs.org](https://sec-certs.org).

3. Play with the dataset. See [example notebook](./notebooks/examples/fips.ipynb).
:::
::::

```{hint}
You can work with those with the help of the [common criteria notebook](notebooks/examples/cc.ipynb) or [fips notebook](notebooks/examples/fips.ipynb).
```

If you insist on processing the whole certificates pipeline, make sure that you installed all [dependencies](installation.md#dependencies). Then, run

::::{tab-set}
:::{tab-item} Common Criteria
```bash
$ sec-certs cc all
```
:::

:::{tab-item} FIPS 140
```bash
$ sec-certs fips all
```
:::
::::

This takes a long time to run (a few hours) and stores the results in the `./dataset` directory; use `-o` to choose a different one. To see all options, run `sec-certs --help`.

## Run sec-certs from Docker

If you installed the Docker image (see [installation](installation.md)), run the container interactively with

```bash
docker run -it seccerts/sec-certs
```

It starts a shell, from which you can run the `sec-certs` CLI. You can also run a single command directly, e.g.

```bash
docker run --rm seccerts/sec-certs sec-certs --help
```

### Persistent files with Docker mounts

Files created in the container are lost when it's removed. To keep them, share a folder between your machine and the container with a [bind mount](https://docs.docker.com/storage/bind-mounts/) or a [volume](https://docs.docker.com/storage/volumes/):

```bash
mkdir seccerts-data && \
docker run -it -w /home/user/data \
--mount type=bind,source="$(pwd)"/seccerts-data/,target=/home/user/data \
seccerts/sec-certs
```

The folder is available as `./seccerts-data` on your machine and as `/home/user/data` in the container. With `-w`, the container starts in that folder, so `sec-certs cc all` stores its `./dataset` directory and its log there.

The container runs as a user with UID 1000. If your user on the host has a different UID and the container can't write to the folder, add `--user "$(id -u):$(id -g)"`. Keep the `-w /home/user/data` in that case, because that user can't write to `/home/user`.

### Run JupyterLab with sec-certs from Docker

The Jupyter variant of the image starts JupyterLab with sec-certs and the example notebooks. Run

```bash
docker run --rm -p 8888:8888 seccerts/sec-certs:latest-jupyter
```

and open the `http://127.0.0.1:8888/lab?token=...` link printed in the output. The example notebooks are in the `notebooks/examples` folder. If you need more packages for your analysis, install them with `%pip install` from a notebook.

The container is removed when it stops (`--rm`), so to keep your work, add the `--mount` option from above and save your files in the `data` folder.

### Convert PDFs with Docling from Docker

The Docling variant of the image converts PDFs with [Docling](https://github.com/docling-project/docling) instead of pdftotext. Otherwise it's used the same way as the default image:

```bash
docker run -it seccerts/sec-certs:latest-docling
```

The Docling models are part of the image, so the conversion doesn't download anything and works offline. To switch back to pdftotext in this image, add `-e SECCERTS_PDF_CONVERTER=pdftotext` to the command.

Docling runs on the CPU by default. On a Linux machine with an NVIDIA GPU, add `--gpus all` to the command to use the GPU. This needs the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) and an NVIDIA driver version 580 or newer. Docker on macOS can't use the GPU, so there the conversion always runs on the CPU.
