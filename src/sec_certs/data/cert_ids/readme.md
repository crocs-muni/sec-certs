## Certificate ID evaluation

This directory contains data on a manual evaluation of certificate ID assignment.

- `missing_ids.csv` contains an evaluation of certificates to which the sec-certs tool was not able to
find a certificate ID (to analyze why that happened and whether we could fix that).
- `duplicate_ids.csv` contains an evaluation of certificates to which the sec-certs tool assigned a duplicate
ID (to analyze why that happened and whether we could fix that). These files are used by the [cert_id_eval.ipynb](./../../notebooks/cc/cert_id_eval.ipynb) notebook which evaluates a dataset with respect to the manually labeled ground truth in them.
