# Quickstart

::::{tab-set}

:::{tab-item} Common Criteria
1. Install the latest version with `pip install -U sec-certs && python -m spacy download en_core_web_sm` (see [installation](installation.md)).
2. In your Python interpreter, type
```python
from sec_certs.dataset.cc import CCDataset

dset = CCDataset.from_web_latest()
```
to obtain to obtain freshly processed dataset from [seccerts.org](https://seccerts.org).

3. Play with the dataset. See [example notebook](./notebooks/examples/cc.ipynb).
:::

:::{tab-item} FIPS 140
1. Install the latest version with `pip install -U sec-certs && python -m spacy download en_core_web_sm` (see [installation](installation.md)).
2. In your Python interpreter, type
```python
from sec_certs.dataset.fips import FIPSDataset

dset = FIPSDataset.from_web_latest()
```
to obtain to obtain freshly processed dataset from [seccerts.org](https://seccerts.org).

3. Play with the dataset. See [example notebook](./notebooks/examples/fips.ipynb).
:::
::::

```{hint}
You can work with those with the help of the [common criteria notebook](notebooks/examples/cc.ipynb) or [fips notebook](notebooks/examples/fips.ipynb) and even launch them in MyBinder without installing anything. Just use the 🚀 icon (top-right corner).
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

This script takes a long time to run (few hours) and will create `./cc_dset` or `./fips_dset` directory. To see all options, call the entrypoint with `--help`.

## Run sec-certs from docker

If you installed the docker image (see [installation](installation.md)), use `docker run -it seccerts/sec-certs` to run the container interactively. From there, you can run the `sec-certs` CLI. Alternatively, you can serve a Jupyter notebook from the docker to use at your host machine and even write your scripts to some shared folder. Example of that use-case follows.

### Persistent files with docker mounts

It may be handy to create a shared folder between your host machine and the docker image, especially for the artifacts of sec-certs analysis. This can be achieved either by [docker volumes](https://docs.docker.com/storage/volumes/) or [docker bind mounts](https://docs.docker.com/storage/bind-mounts/). An example follows that achieves a shared folder writable from the container.

```bash
mkdir seccerts-data && \
docker run -it \
--mount type=bind,source="$(pwd)"/seccerts-data/,target=/home/user/data \
seccerts/sec-certs
```

The folder should be accessible on your machine on `./seccerts-data` path; from docker on `/home/user/data` path.

### Run jupyter notebook with sec-certs from Docker

You can also use our docker image to serve `jupyter notebook` instance that you can access from your device. Run

```bash
docker run --rm -it -p 8888:8888 \
seccerts/sec-certs jupyter notebook \
--no-browser --ip 0.0.0.0 --NotebookApp.token='' --notebook-dir="/home/user/"
```

Now, you should be able to access the notebook at `localhost:8888` from your machine. Navigate to `/home/user/sec-certs/notebooks/examples` to see some example notebooks.
