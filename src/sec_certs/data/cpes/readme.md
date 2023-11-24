## CPEs

- This directory contains digests of 100 randomly sampled certificates, together with predicted and ground-truth labels.
The file `random.csv` summarizes the data above, while `manual_cpe_labels.json` is a JSON-min export from label studio instance.
- These files can be utilized from [cpe_eval notebook](../../notebooks/cc/cpe_eval.ipynb) to see the performance of the classifier.
-Folder `./outdated` contains some old incomplete labeling that was obtained highly unoptimized classifier.
- [label_studio_interface.txt](label_studio_interface.txt) contains XML-like specification of the labeling interface
for CPE matching. As such, it was used in the Label studio tool.
