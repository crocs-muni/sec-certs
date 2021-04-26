# ![](docs/_static/logo.svg)

Tool for analysis of security certificates and their security targets (Common Criteria, NIST FIPS140-2...).

This project is developed by the [Centre for Research On Cryptography and Security](https://crocs.fi.muni.cz) at Faculty of Informatics, Masaryk University.

[![Website](https://img.shields.io/website?down_color=red&down_message=offline&style=flat-square&up_color=SpringGreen&up_message=online&url=https%3A%2F%2Fseccerts.org)](https://seccerts.org)
[![PyPI](https://img.shields.io/pypi/v/sec-certs?style=flat-square)](https://pypi.org/project/sec-certs/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/sec-certs?label=Python%20versions&style=flat-square)](https://pypi.org/project/sec-certs/)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/crocs-muni/sec-certs/tests?style=flat-square)](https://github.com/crocs-muni/sec-certs/actions/workflows/GA_CI.yml)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/crocs-muni/sec-certs/Docker%20Image%20CI?label=Docker%20build&style=flat-square)](https://hub.docker.com/repository/docker/seccerts/sec-certs)

## Installation (CC)

The tool requires several Python packages as well as the `pdftotext` binary somewhere on the `PATH`.
[
The stable release is published on [PyPi](https://pypi.org/project/sec-certs/) as well as on [DockerHub](https://hub.docker.com/repository/docker/seccerts/sec-certs), you can install it with:

```
pip install -U sec-certs
```

or

```
docker pull seccerts/sec-certs
```

Alternatively, you can setup the tool for development in a virtual environment, e.g.:
Install Python virtual environment (if not yet):
```
python3 -m pip install --upgrade pip
pip install virtualenv  
```
Setup new local one named 'virt' :
```
python3 -m venv virt
. virt/bin/activate
pip install -e .
```

## Examples

Some examples are documented in [examples](https://github.com/crocs-muni/sec-certs/blob/master/examples/)

## Old API

The following steps will do a full extraction and analysis of CC certificates:

 1. Make a directory in which the certificates will be downloaded and processing will take place.
    The contents of the directory are under the control of the tool, and **may be overwritten**!
 2. Run `python process_certificates.py --fresh --do-download-meta <dir>` to download certificate metadata from the Common Criteria portal.
 3. Run `python process_certificates.py --fresh --do-extraction-meta <dir>` to extract metadata from the downloaded Common Criteria pages.
 4. Run `python process_certificates.py --fresh --do-download-certs <dir>` to download the certificate and security target PDF files. This
    step takes time as there is quite a lot of files. It also takes up a lot of space (around 5GB). It is done in parallel
    and the number of threads can be changed with the `-t/--threads` switch (the default is 4).
 5. Run `python process_certificates.py --fresh --do-pdftotext <dir>` to convert the PDF files to text.
 6. Run `python process_certificates.py --fresh --do-extraction <dir>` to extract information from the certificates and security targets.
 7. Run `python process_certificates.py --fresh --do-pairing <dir>`.
 8. Run `python process_certificates.py --fresh --do-processing <dir>` to run various heuristics which will create post-processed section
   `processed` for every certificate (results are stored in `certificate_data_complete_processed.json`).
 9. Run `python process_certificates.py --fresh --do-analysis <dir>` to perform analysis of certificates (various graphs, statistics...).
 10. Open, look and enjoy graphs like `num_certs_in_years.png` or `num_certs_eal_in_years.png`. For `certid_graph.dot.pdf` 
     and other large graphs use Chrome to display as Adobe Acrobat Reader will fail to show whole graph. 


## Extending the analysis

The analysis can be extended in several ways:
 1. Additional keywords can be extracted from PDF files (modify `cert_rules.py`)
 2. Data from `certificate_data_complete.json` can be analyzed in a novel way - this is why this project was concieved at the first place.
 3. Help to fix problems in data extraction - some PDF files are corrupted, there are many typos even in certificate IDs...

## How to run the application with a Docker container
 1. pull the image from the DockerHub repository : `docker pull seccerts/sec-certs`
 2. run `sudo docker run sec-certs:latest --volume ~/processed_data:/opt/sec-certs/examples/debug_dataset`
 3. All processed data will be in the `~/processed_data` directory
