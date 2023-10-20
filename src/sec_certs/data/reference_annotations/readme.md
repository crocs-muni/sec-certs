# Reference annotations

This folder contains data and the methodology (presented below) related to learning the reference annotations.

- The folder [split](split) contains split of the CC Dataset to `train/valid/test` splits for learning.
- The csv file [manually_annotated_references.csv](./manually_annotated_references.csv) contains manually acquired labels to references obtained with the methodology outlined below.
- The folder `adam` contains manual annotations created by Adam
- The folder `jano` contains manual annotations created by Jano
- The folder `conflicts` contains conflicting annotations between Adam and Jano, as weel as their resolution
- The contents of the `final` folder can thus be obtained by taking annotations either from `adam` or `jano` folder and masking them by `resolution_label` from `conflicts` folder.

### Reference taxonomy

After manually inspecting random certificates, we have identified the following reference meanings:

- **Component used**: The referenced certificate is a component used in the examined certificate (e.g., IC used by a smartcard). Some evaluation results were likely shared/re-used.
- **Component shared**: The referenced certificate shares some components with the examined certificate. Some evaluation results were likely shared/re-used.
- **Evaluation reused**: The evaluation results of the referenced certificate were used for evaluation of the examined certificate, due to reasons that could not be resolved.
- **Recertification**: The examined certificate is a re-certification of the referenced certificate.
- **Previous version**: The product in the referenced certificate is a previous version of the product in the examined certificate and the re-certification is not explicitly mentioned.
- **None**: The annotator could not assign any of the previous contexts.
- **Irrelevant**: The reference is irrelevant to the studied certificate (typo, left-out reference from a template, ...)

These can be further merged into the following super-categories:

- **Some sub-component relationship** `component_used`, `component_shared`, and `evaluation_reused`
- **Previous version**: `previous_version` and `recertification`
- **None**: `None` or `irrelevant`

### Reference classification methodology

**Data splits and manual annotations**:

1. Two authors inspect random certificates (~100) and capture the observed relations into reference taxonomy
2. Split all certificates for which we register a direct outgoing reference in either security target or certification report into `train/valid/test` splits in `30/20/50` fashion (see [split](split/)).
3. Sample 100 train, 100 valid, 200 test pairs of `(dgst, canonical_reference_keyword)` for manual annotations.
4. Two co-authors independently assign each of these pairs with a single label from the reference taxonomy.
5. Measure the inter-annotator agreement with Cohen's Kappa.
6. Resolve conflicts in the annotations in a meeting held by the co-authors. Use this consensual annotations for training and evaluation described below.

**Learning the annotations**:

1. For each pair `(dgst, referenced_cert_id)`, recover the relevant segments both from certification report and security target that mention the `referenced_cert_id`
2. Apply text processing on the segments (e.g., unify re-certification vs. recertification, etc.)
3. Train a baseline model based on TF-IDF (or count vectorization in general), random forest, and a soft-voting layer on top of that.
    - Random forest classifies single segment to a probability of a given label
    - Soft voting compares probabilities of the given labels on all segments, takes their square and chooses the maximum.
4. Train a sentence transformer with the same soft-voting layer on top of that.
5. Finetune hyperparameters.
6. Evaluate on test set.


## Inter-annotator agreement

The inter-annotator agreement is measured both with Cohen's Kappa and with percentage. The results are as follows:

| Cohen's Kappa | Percentage |
|---------------|------------|
| 0.71          | 0.82       |

The code used to measure the agreement is:

```python
import pandas as pd
from pathlib import Path
from sklearn.metrics import cohen_kappa_score

def load_all_dataframes(base_folder: Path) -> pd.DataFrame:
    splits = ["train", "valid", "test"]

    df_train, df_valid, df_test = pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    for split in splits:
        df = pd.read_csv(base_folder / f"{split}.csv")
        if split == "train":
            df_train = df
        elif split == "valid":
            df_valid = df
        else:
            df_test = df

    return pd.concat([df_train, df_valid, df_test])

adam_df = load_all_dataframes(Path("./src/sec_certs/data/reference_annotations/adam"))
jano_df = load_all_dataframes(Path("./src/sec_certs/data/reference_annotations/jano"))
agreement_series = adam_df.label == jano_df.label

print(f"Cohen's Kappa: {cohen_kappa_score(adam_df.label, jano_df.label)}")
print(f"Percentage agreement: {agreement_series.loc[agreement_series == True].count() / agreement_series.count()}")
```
