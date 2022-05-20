"""
Tool for analysis of security certificates and their security targets (Common Criteria, NIST FIPS140-2...).
Contains three main sub-packages:
- dataset - package that holds the respective datasets and performs all processing of them
- sample - package that holds a single sample (e.g., Common Criteria certificate - CommonCriteriaCert). Mostly data structure, but can provide basic functionality.
- model - package that provides data pipelines (transformers, classifiers, ...) for complex transformations of datasets.
"""
