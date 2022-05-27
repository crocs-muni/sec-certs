# Quickstart

::::{tab-set}

:::{tab-item} Common Criteria
1. Install the latest version with `pip install -U sec-certs` (see [installation](installation.md)).
2. Use
```python
from sec_certs.dataset import CCDataset

dset = CCDataset.from_web_latest()
```
to obtain to obtain freshly processed dataset from [seccerts.org](https://seccerts.org).

3. Play with the dataset. See [example notebook](./notebooks/examples/common_criteria.ipynb).
:::

:::{tab-item} FIPS 140
1. Install the latest version with `pip install -U sec-certs` (see [installation](installation.md)).
2. Use
```python
from sec_certs.dataset import FIPSDataset

dset = FIPSDataset.from_web_latest()
```
to obtain to obtain freshly processed dataset from [seccerts.org](https://seccerts.org).

3. Play with the dataset. See [example notebook](./notebooks/examples/fips.ipynb).
:::
::::

```{hint}
You can work with those with the help of the [common criteria notebook](notebooks/examples/common_criteria.ipynb) or [fips notebook](notebooks/examples/fips.ipynb) and even launch them in MyBinder without installing anything. Just use the 🚀 icon (top-right corner).
```

If you insist on processing the whole certificates pipeline, make sure that you installed all [dependencies](installation.md#dependencies). Then, run

::::{tab-set}
:::{tab-item} Common Criteria
```bash
$ cc-certs all
```
:::

:::{tab-item} FIPS 140
```bash
$ fips-certs new-run
```
:::
::::

This script takes a long time to run (few hours) and will create `./cc_dset` or `./fips_dset` directory. To see all options, call the entrypoint with `--help`.

:::{hint}
If you installed the docker image, use `docker run -it sec-certs bash` to run the container interactively.
:::
