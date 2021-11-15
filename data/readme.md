# Data

## CPE Matching

To evaluate quality of our automatic matching of CPE names to certificates (which in turn allows us to assign CVEs to certificates), we manually evaluated candidate CPE records for all of the certificates both in FIPS and CC framework. 

Not to cause data leakage, prior to developing automatic method of CPE matching, we split the dataset into validation a test parts in 50:50 fashion. The automatic CPE matching was finetuned using the validation set and only then evaluated using the test set. 

### Manual CPE labels

The directory `./manual_cpe_labels` contains manually assigned CPE labels for each of the certificates in CC and FIPS framework. This labels can be loaded into the certificate attribute `verified_cpe_matches` via dataset function `load_json_studio_labels('/path/to/labels.json')`. See how this is being done in example scripts mentioned below.

### Validation and test split

The directory `./validation_test_split` contains digests (primary keys of certificates) of the formed validation and test sets. The output present herein was produced with [validation_test_split.ipnyb](https://github.com/crocs-muni/sec-certs/tree/dev/notebooks/validation_test_split.ipynb).

To see how the evaluation was performed, take a look at [cc_cpe_labeling.py](https://github.com/crocs-muni/sec-certs/blob/dev/examples/cc_cpe_labeling.py) and [fips_cpe_labeling.py](https://github.com/crocs-muni/sec-certs/blob/dev/examples/fips_cpe_labeling.py).