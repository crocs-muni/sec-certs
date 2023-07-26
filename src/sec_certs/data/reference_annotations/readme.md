# Reference annotations

This folder contains data and the methodology (presented below) related to learning the reference annotations.

- The folder [split](split) contains split of the CC Dataset to `train/valid/test` splits for learning.
- The csv file [manually_annotated_references.csv](./manually_annotated_references.csv) contains manually acquired labels to references obtained with the methodology outlined below.

### Reference taxonomy

After manually inspecting random certificates, we have identified the following reference meanings:

- **Component used**: The referenced certificate is a component used in the examined certificate (e.g., IC used by a smartcard). Some evaluation results were likely shared/re-used.
- **Component shared**: The referenced certificate shares some components with the examined certificate. Some evaluation results were likely shared/re-used.
- **Evaluation reused**: The evaluation results of the referenced certificate were used for evaluation of the examined certificate, due to reasons that could not be resolved.
- **Re-certification**: The examined certificate is a re-certification of the referenced certificate.
- **Previous version**: The product in the referenced certificate is a previous version of the product in the examined certificate and the re-certification is not explicitly mentioned.
- **Unknown**: The annotator could not assign any of the previous contexts.

These can be further merged into the following super-categories:

- **Component used or shared**
- **Previous version of re-certification**
- **Evaluation reused** - these cases should be manually visited
- **Unknown**

### Reference classification methodology

**Data splits and manual annotations**:

1. Inspect random certificates (>100) and capture the observed relations into reference taxonomy
2. Split all certificates for which we register a direct outgoing reference in either security target or certification report into `train/valid/test` splits in `30/20/50` fashion.
    - See [split](split/)
3. Label all references in as follows:
    - Extract the text segments (using `ReferenceSegmentExtractor`) related to the references
    - Use label-studio `Natural Language Processing -> text classification` setup to assign 1 label to each of the references.
        - All text segments both from certification report and security target are displayed for the given instance
    - The instances labeled with `Unknown` are re-visited and labeled after manual inspection of both certification report and security target pdfs
    - Artifacts of the referenced certificate are not examined.
    - The labeling is done by a pair of co-authors, the inter-annotator agreement is measured with Cohen's Kappa

**Learning the annotations**:

1. For each pair `(dgst, referenced_cert_id)`, recover the relevant segments both from certification report and security target that mention the `referenced_cert_id`
2. Apply text processing on the segments (e.g., unify re-certification vs. recertification, etc.)
3. Train a baseline model based on TF-IDF (or count vectorization in general), random forest, and a soft-voting layer on top of that.
    - Random forest classifies single segment to a probability of a given label
    - Soft voting compares probabilities of the given labels on all segments, takes their square and chooses the maximum.
4. Train a sentence transformer with the same soft-voting layer on top of that.
5. Finetune hyperparameters.
6. Evaluate on test set.
