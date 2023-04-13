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
