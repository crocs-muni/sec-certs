# Chain-of-Trust paper artifacts

This directory contains the artifacts that accompany the paper **Chain of Trust: Unraveling the References among Common Criteria Certified Device** accepted for the 2024 IFIP-SEC conference. The reader can find here the following files:

**Data**:
- [Manual annotations](./../../src/sec_certs/data/reference_annotations/): of the reference contexts
- [Hyperparameters](./data/hyperparameter_tuning/): The best (and all searched) hyperparameter values and the whole protocol captured by Optuna
- [plots](./data/plots/): The CSV files produced by [references.ipynb](./../../notebooks/cc/references.ipynb) notebook and consumed by [chain_of_trust_plots.ipynb](./../../notebooks/cc/chain_of_trust_plots.ipynb) notebook.
- [Model evaluation](./data/model_evaluation/): Model-evaluation data produced by the [prediction.ipynb](./../../notebooks/cc/reference_annotations/prediction.ipynb) notebook.
- [Vulnerability propagation experiment](./data/vulnerability_propagation_experiment): Data related to the experiment mapping the propagation of vulnerabilities in the realm of CC-certified products.
- [Dataset](https://sec-certs.org/static/cc_november_2023.tar.zst) of CC-related artifacts was produced with `sec-certs` tool and dates to November 1, 2023.

**Documents**:

- [Annotation codebook](./documents/codebook.pdf): the complete codebook for the manual annotation of the context of inter-certificate references.
- [Hyperparameter tunning](./documents/hyperparameter_tunning.md): The hyperparameter tunning protocol and a description of all searched hyperparameters.
