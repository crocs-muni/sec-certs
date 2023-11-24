# Reference annotations

This folder contains data related to learning the reference annotations. This document also describeds the utilized methodology.

- The folder [split](split) contains split of the CC Dataset to `train/valid/test` splits for learning.
- The csv file [outdated_manually_annotated_references.csv](./outdated_manually_annotated_references.csv) contains manually acquired labels to references obtained with **old methodology** for the sake of paper 1 submission.
- The folder [adam](adam/) contains manual annotations created by Adam
- The folder [jano](jano/) contains manual annotations created by Jano
- The folder [conflicts](conflicts/) contains conflicting annotations between Adam and Jano, as weel as their resolution
- The contents of the [final](final/) folder can thus be obtained by taking annotations either from `adam` or `jano` folder and masking them by `resolution_label` from `conflicts` folder.

## Reference classification methodology

### Data splits and manual annotations

1. Two co-authors independently inspect identical set of 100 random certificates and capture the observed relations into reference taxonomy to form the annotation guidelines. See [reference taxonomy](#reference-taxonomy) below.
2. We split all certificates for which we register a direct outgoing reference in either security target or certification report into `train/valid/test` splits in `30/20/50` fashion (see [split](split/)).
3. We sample 100 train, 100 valid, 200 test pairs of reference instances (represented by `(dgst, canonical_reference_keyword)` pairs) for manual annotations.
4. Two co-authors independently assign each of these instances with a single label from the reference taxonomy.
5. We measure the inter-annotator agreement with Cohen's Kappa and percentage, see [inter-annotator agreement](#inter-annotator-agreement).
6. We resolve conflicts in the annotations in a meeting held by the co-authors. We use this consensual annotations for training and evaluation described below.

### Supervised learning of the annotations

1. For each pair `(dgst, referenced_cert_id)`, we recover the relevant text segments both from certification report and security target that mention the `referenced_cert_id`.
2. We apply text processing on the segments (e.g., unify re-certification vs. recertification, etc.)
3. We train a baseline model based on TF-IDF (or count vectorization in general), random forest and a soft-voting layer on top of that.
    - Random forest classifies single segment with a probability of a given label.
    - Soft voting compares probabilities of the given labels on all segments, takes their square and chooses the maximum.
4. We train a sentence transformer with the same soft-voting layer on top of that.
5. Finetune hyperparameters.
6. We evalute the results on the test set using weighted F1 score.

### Reference taxonomy

After manually inspecting ~100 random certificates, we have identified the following reference meanings:

- **Component used**: The referenced certificate is a component used in the examined certificate (e.g., IC used by a smartcard). Some evaluation results were likely shared/re-used.
- **Component shared**: The referenced certificate shares some components with the examined certificate. Some evaluation results were likely shared/re-used.
- **Evaluation reused**: The evaluation results of the referenced certificate were used for evaluation of the examined certificate, due to reasons that could not be resolved.
- **Re-evaluation**: The examined certificate is a re-evaluation of the referenced certificate. For definition of re-evaluation, see [Assurance Continuity: CCRA Requirements](https://www.commoncriteriaportal.org/files/operatingprocedures/CCDB-011-v2.2-2021-Sep-30-Final-Assurance_Continuity.pdf).
- **Previous version**: The product in the referenced certificate is a previous version of the product in the examined certificate and the re-certification is not explicitly mentioned.
- **None**: The annotator could not assign any of the previous contexts.
- **Irrelevant**: The reference is irrelevant to the studied certificate (typo, left-out reference from a template, ...)

These can be further merged into the following super-categories:

- **Some sub-component relationship** `component_used`, `component_shared`, and `evaluation_reused`
- **Previous version**: `previous_version` and `re-evaluation`
- **None**: `None` or `irrelevant`

###  Inter-annotator agreement

The inter-annotator agreement is measured both with Cohen's Kappa and with percentage. The results are as follows:

| Cohen's Kappa | Percentage |
| ------------- | ---------- |
| 0.71          | 0.82       |

The code used to measure the agreement is stored in `notebooks/cc/reference_annotations/inter_annotator_agreement.ipynb`.

