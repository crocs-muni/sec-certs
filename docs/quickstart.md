# Quickstart

1. Install the latest version with `pip install -U sec-certs` (see [installation](installation.md)).
2. Use
```python
dset = CCDataset.from_web_latest()
```

(Common Criteria) or

```python
dset = FIPSDataset.from_web_latest()
```

(FIPS 140) to obtain freshly processed datasets from [seccerts.org](https://seccerts.org).

```{hint}
You can work with those with the help of the [common criteria notebook](notebooks/examples/common_criteria.ipynb) or [fips notebook](notebooks/examples/fips.ipynb) and even launch them in MyBinder without installing anything. Just use the 🚀 icon (top-right corner).
```

If you insist on processing the whole certificates pipeline, make sure that you installed all [dependencies](installation.md#dependencies). Then, run

```bash
cc-certs all
```

for Common Criteria processing, or

```bash
fips-certs all
```

for FIPS 140 processing. This script takes a long time to run (few hours) and will create `./cc_dset` or `./fips_dset` directory. To see all options, call the entrypoint with `--help`.