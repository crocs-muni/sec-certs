# Model package

```{eval-rst}
.. automodule:: sec_certs.model
    :no-members:
```

```{tip}
The examples related to this package can be found at [model notebook](./../notebooks/examples/model.ipynb).
```

```{warning}
Transforming `CPE` records to existing vulnerabilities is handled by [Dataset](https://github.com/crocs-muni/sec-certs/blob/main/sec_certs/dataset/dataset.py) class, `compute_related_cves()` method.

However, come CVEs are missed due to omitted vulnerable configurations in [CVEDataset](https://github.com/crocs-muni/sec-certs/blob/main/sec_certs/dataset/cve.py) class. We omit configurations that comprise of two components joined with `AND` operator. For closer description, see [issue #252](https://github.com/crocs-muni/sec-certs/issues/252) at GitHub.
```

## CPEClassifier

```{eval-rst}
.. currentmodule:: sec_certs.model
.. autoclass:: CPEClassifier
    :members:
```

## SARTranformer

```{eval-rst}
.. currentmodule:: sec_certs.model
.. autoclass:: SARTransformer
    :members:
```

## ReferenceFinder

```{eval-rst}
.. currentmodule:: sec_certs.model
.. autoclass:: ReferenceFinder
    :members:
```

## TransitiveVulnerabilityFinder

```{eval-rst}
.. currentmodule:: sec_certs.model
.. autoclass:: TransitiveVulnerabilityFinder
    :members:
```