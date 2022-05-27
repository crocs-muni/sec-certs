# Sec-certs

![](docs/_static/logo.svg)

Tool for analysis of security certificates and their security targets (Common Criteria, NIST FIPS140-2...).

This project is developed by the [Centre for Research On Cryptography and Security](https://crocs.fi.muni.cz) at Faculty of Informatics, Masaryk University.

[![Website](https://img.shields.io/website?down_color=red&down_message=offline&style=flat-square&up_color=SpringGreen&up_message=online&url=https%3A%2F%2Fseccerts.org)](https://seccerts.org)
[![PyPI](https://img.shields.io/pypi/v/sec-certs?style=flat-square)](https://pypi.org/project/sec-certs/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sec-certs?label=Python%20versions&style=flat-square)](https://pypi.org/project/sec-certs/)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/crocs-muni/sec-certs/tests?style=flat-square)](https://github.com/crocs-muni/sec-certs/actions/workflows/tests.yml)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/crocs-muni/sec-certs/Docker%20Image%20CI?label=Docker%20build&style=flat-square)](https://hub.docker.com/repository/docker/seccerts/sec-certs)
[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/crocs-muni/sec-certs/dev?filepath=notebooks%2Fcpe_cve.ipynb)

## Installation

Use Docker with `docker pull seccerts/sec-certs` or just `pip install -U sec-certs`. For more elaborate description, see [docs](https://seccerts.org/docs/installation.html)

## Usage (CC)

There are two main steps in exploring the world of Common Criteria certificates:

1. Processing all the certificates
2. Data exploration

For the first step, we currently provide CLI and our already processed fresh snapshot. For the second step, we provide simple API that can be used directly inside our Jupyter notebook or locally, at your machine.

### Explore data with MyBinder Jupyter notebook

Most probably, you don't want to process fresh snapshot of Common Criteria certificates by yourself. Instead, you can use our results and explore them using [online Jupyter notebook](https://mybinder.org/v2/gh/crocs-muni/sec-certs/dev?filepath=notebooks%2Fcpe_cve.ipynb).

### Explore the latest snapshot locally

In Python, run

```python
from sec_certs.dataset.common_criteria import CCDataset
import pandas as pd

dset = CCDataset.from_web_latest()  # now you can inspect the object, certificates are held in dset.certs
df = dset.to_pandas()  # Or you can transform the object into Pandas dataframe
dset.to_json(
    './latest_cc_snapshot.json')  # You may want to store the snapshot as json, so that you don't have to download it again
dset = CCDataset.from_json('./latest_cc_snapshot.json')  # you can now load your stored dataset again
```

### Process CC data with Python

If you wish to fully process the Common Criteria (CC) data by yourself, you can do that as follows. Running

```python
cc-certs all --output ./cc_dataset
```

will fully process the Common Criteria dataset, which can take up to 6 hours to finish. You can select only same tasks to run. Calling `cc-cli --help` yields

```
Usage: cc_cli.py [OPTIONS]
                 [all|build|download|convert|analyze|maintenances]...

  Specify actions, sequence of one or more strings from the following list:
  [all, build, download, convert, analyze] If 'all' is specified, all
  actions run against the dataset. Otherwise, only selected actions will run
  in the correct order.

Options:
  -o, --output DIRECTORY  Path where the output of the experiment will be
                          stored. May overwrite existing content.

  -c, --config FILE       Path to your own config yaml file that will override
                          the default one.

  -i, --input FILE        If set, the actions will be performed on a CC
                          dataset loaded from JSON from the input path.

  -s, --silent            If set, will not print to stdout
  --help                  Show this message and exit.
```

### Process CC data with Docker

 1. pull the image from the DockerHub repository : `docker pull seccerts/sec-certs`
 2. run `docker run --volume ./processed_data:/home/user/sec-certs/examples/debug_dataset -it seccerts/sec-certs`
 3. All processed data will be in the `~/processed_data` directory

## Usage (FIPS)

Currently, the main goal of the FIPS module is to find dependencies between the certified products.

### MyBinder Jupyter Notebook

Without the need of processing the data locally, you can use the online MyBinder Jupyter notebook:

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/crocs-muni/sec-certs/fips?filepath=.%2Fnotebooks%2Ffips_data.ipynb)


### Explore the latest snapshot locally

You can also explore the latest snapshot locally using Python:
```py
from sec_certs.dataset.fips import FIPSDataset

dset: FIPSDataset = FIPSDataset.from_web_latest()  # to get the latest snapshot
dset.to_json('./fips_dataset.json')  # to save the dataset
new_dset = FIPSDataset.from_json('./fips_dataset.json')  # to load it from disk

```

### Process FIPS data manually with Python

You can also process FIPS data manually using `fips-certs` in terminal after installation.
You can also use the `fips_cli.py` script.

Calling `fips-certs --help` outputs following:
```
Usage: fips-certs [OPTIONS] [new-run|all|build|convert|update|web-scan|pdf-
                  scan|table-search|analysis|graphs]...

  Specify actions, sequence of one or more strings from the following list:

  ["new-run", "all", "build", "convert", "update", "pdf-scan",
  "table-search", "analysis", "graphs"]

  If 'new-run' is specified, a new dataset will be created and all the
  actions will be run. If 'all' is specified, dataset will be updated and
  all actions run against the dataset. Otherwise, only selected actions will
  run in the correct order.

  Dataset loading:

      'build'         Create a skeleton of a new dataset from NIST pages.

      'update'        Load a previously used dataset (created by 'build')
      and update it with nonprocessed entries from NIST pages.

      Both options download the files needed for analysis.

  Analysis preparation:

      'convert'       Convert all downloaded PDFs.

      'pdf-scan'      Perform a scan of downloaded CMVP security policy
      documents - Keyword extraction.

      'table-search'  Analyze algorithm implementation entries in tables in
      security policy documents.

      Analysis preparation actions are by default done only for
      certificates, where each corresponding action failed.     This
      behaviour can be changed using '--redo-*' options.     These actions
      are also independent of each other.

  Analysis:

      'analysis'      Merge results from analysis preparation and find
      dependencies between certificates.

      'graphs'        Plot dependency graphs.

Options:
  -o, --output DIRECTORY      Path where the output of the experiment will be
                              stored. May overwrite existing content.

  -c, --config FILE           Path to your own config yaml file that will
                              override the default one.

  -i, --input FILE            If set, the actions will be performed on a CC
                              dataset loaded from JSON from the input path.

  -n, --name TEXT             Name of the json object to be created in the
                              <<output>> directory. Defaults to
                              timestamp.json.

  --no-download-algs          Don't fetch new algorithm implementations
  --redo-web-scan             Redo HTML webpage scan from scratch
  --redo-keyword-scan         Redo PDF keyword scan from scratch
  --higher-precision-results  Redo table search for certificates with high
                              error rate. Behaviour undefined if used on a
                              newly instantiated dataset.

  -s, --silent                If set, will not print to stdout
  --help                      Show this message and exit.
```

The *Analysis* part is designed to find dependecies between certificates.

#### First run
The first time you are using the FIPS module, use the following command:
```
fips-certs new-run --output <directory name> --name <dataset name>
```
where `<directory name>` is the name of the working directory of the FIPS module
(e.g. where all the metadata will be stored), and `<dataset name>` is the name of the resulting dataset.

This will download a large amount of data (4-5 GB) and can take up to 4 hours to finish.

#### Next runs

When a dataset is successfully created using `new-run`, you can use the command `all` to update the dataset
(download latest files, redo scans for failed certificates, etc.). It is also **strongly advised** to use the `--higher-precision-results`
switch on the **second run**. The following command should be used to update the dataset:
```
fips-certs all --input <path to the dataset>
```
where `<path to the dataset>` is the **path to the dataset file**, i.e. `<directory name>/<dataset name>.json` from the first run.
