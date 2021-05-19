# ![](docs/_static/logo.svg)

Tool for analysis of security certificates and their security targets (Common Criteria, NIST FIPS140-2...).

This project is developed by the [Centre for Research On Cryptography and Security](https://crocs.fi.muni.cz) at Faculty of Informatics, Masaryk University.

[![Website](https://img.shields.io/website?down_color=red&down_message=offline&style=flat-square&up_color=SpringGreen&up_message=online&url=https%3A%2F%2Fseccerts.org)](https://seccerts.org)
[![PyPI](https://img.shields.io/pypi/v/sec-certs?style=flat-square)](https://pypi.org/project/sec-certs/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sec-certs?label=Python%20versions&style=flat-square)](https://pypi.org/project/sec-certs/)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/crocs-muni/sec-certs/tests?style=flat-square)](https://github.com/crocs-muni/sec-certs/actions/workflows/tests.yml)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/crocs-muni/sec-certs/Docker%20Image%20CI?label=Docker%20build&style=flat-square)](https://hub.docker.com/repository/docker/seccerts/sec-certs)
[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/crocs-muni/sec-certs/cc-feature-parity?filepath=notebooks%2Fcc_data_exploration.ipynb)

## Installation (CC)

The tool requires `Python >=3.8` and [pdftotext](https://www.xpdfreader.com/pdftotext-man.html) binary somewhere on the `PATH`.

The stable release is published on [PyPi](https://pypi.org/project/sec-certs/) as well as on [DockerHub](https://hub.docker.com/repository/docker/seccerts/sec-certs), you can install it with:

```
pip install -U sec-certs
```

or

```
docker pull seccerts/sec-certs
```

Alternatively, you can setup the tool for development in virtual environment:

```
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Usage

There are two main steps in exploring the world of Common Criteria certificates:

1. Processing all the certificates
2. Data exploration

For the first step, we currently provide CLI and our already processed fresh snapshot. For the second step, we provide simple API that can be used directly inside our Jupyter notebook or locally, at your machine. 

### Explore data with MyBinder Jupyter notebook

Most probably, you don't want to process fresh snapshot of Common Criteria certificates by yourself. Instead, you can use our results and explore them using [online Jupyter notebook](https://mybinder.org/v2/gh/crocs-muni/sec-certs/dev?filepath=notebooks%2Fcc_data_exploration.ipynb).

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
Usage: cc_cli.py [OPTIONS] [all|build|download|convert|analyze|maintenances]...

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
 2. run `docker run --volume ./processed_data:/opt/sec-certs/examples/debug_dataset -it seccerts/sec-certs`
 3. All processed data will be in the `~/processed_data` directory
