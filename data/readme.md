# Data

The file [label_studio_interface.txt](label_studio_interface.txt) contains XML-like specification of the labeling interface
for CPE matching. As such, it was used in the Label studio tool.

## Certificate ID evaluation

The directory `./cert_id_eval` contains data on a manual evaluation of certificate ID assignment.
`missing_ids.csv` contains an evaluation of certificates to which the sec-certs tool was not able to
find a certificate ID (to analyze why that happened and whether we could fix that).
`duplicate_ids.csv` contains an evaluation of certificates to which the sec-certs tool assigned a duplicate
ID (to analyze why that happened and whether we could fix that). These files are used by the `cert_id_eval.ipynb`
Jupyter notebook which evaluates a dataset with respect to the manually labeled ground truth in them.

## CPE Matching

The directory `./cpe_eval` contains digests of 100 randomly sampled certificates, together with predicted and ground-truth labels.
The file `random.csv` summarizes the data above, while `manual_cpe_labels.json` is a JSON-min export from label studio instance.

These files can be utilized from [cpe_eval notebook](../notebooks/cc/cpe_eval.ipynb) to see the performance of the classifier.

Folder `./old_manual_cpe_labels` contains some old incomplete labeling that was obtained highly unoptimized classifier.