# User's guide

```{important}
This guide is in the making.
```

## NVD datasets

Our tool matches certificates to their possible CVEs using datasets downloaded from [National Vulnerability Database (NVD)](https://nvd.nist.gov). If you're fully processing the `CCDataset` or `FIPSDataset` by yourself, you must somehow obtain the NVD datasets.

Our tool can seamlessly download the required NVD datasets when needed. We support two download mechanisms:

1. Fetching datasets with the [NVD API](https://nvd.nist.gov/developers/start-here) (preferred way).
1. Fetching snapshots from seccerts.org.

The following two keys control the behaviour:

```yaml
preferred_source_nvd_datasets: "api" # set to "sec-certs" to fetch them from seccerts.org
nvd_api_key: null # or the actual key value
```

If you aim to fetch the sources from NVD, we advise you to get an [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) and set the `nvd_api_key` setting accordingly. The download from NVD will work even without API key, it will just be slow. No API key is needed when `preferred_source_nvd_datasets: "sec-certs"`


## Infering inter-certificate reference context

```{important}
This is an experimental feature.
```

We provide a model that can predict the context of inter-certificate references based on the text embedded in the artifacts. The model output is not incorporated into the `CCCertificate` instances, but can be dumped into a `.csv` file from where it can be correlated with a DataFrame of certificate features.

To train and deploy the model, it should be sufficient to change some paths and run the [prediction notebook](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/cc/reference_annotations/prediction.ipynb). The output of this notebook is a `prediction.csv` file that can be loaded into the [references notebook](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/cc/references.ipynb). This notebook documents the full analysis of references conducted on the Common Criteria certificates. Among others, the notebook generates some further `.csv` files that can subsequently be plotted via [plotting notebook](https://github.com/crocs-muni/sec-certs/blob/main/notebooks/cc/paper2_plots.ipynb).
