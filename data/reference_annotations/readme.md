# Reference annotations

This folder contains data and the methodology (presented below) related to learning the reference annotations.

- The folder [split](split) contains split of the CC Dataset to `train/valid/test` splits for learning.
- The csv file [manually_annotated_references.csv](./manually_annotated_references.csv) contains manually acquired labels to references obtained with the methodology outlined below.

### Reference taxonomy

After manually inspecting random certificates, we have identified the following reference meanings:

- **Component used**: The referenced certificate is a component used in the examined certificate (e.g., IC used by a smartcard). Some evaluation results were likely shared/re-used. This is a specific case of *evaluation reused* label
- **Component shared**: The referenced certificate shares some components with the examined certificate. Some evaluation results were likely shared/re-used. This is a specific case of *evaluation reused* label.
- **Evaluation reused**: The evaluation results of the referenced certificate were used for evaluation of the examined certificate, due to reasons that could not be resolved as *component used* nor *component shared*.
- **Recertification**: The examined certificate is a re-certification of the referenced certificate.
- **Previous version**: The product in the referenced certificate is a previous version of the product in the examined certificate and the recertification is not explicitly mentioned.
- **On platform**: The examined certificate runs on a platform that is certified in the referenced certificate.
- **Self**: The referenced certificate is the same as the examined certificate.


### Reference classification methodology

**Data splits and manual annotations**:

1. Inspect random certificates (>100) and capture the observed relations into reference taxonomy
2. Split all certificates for which we register a direct outgoing reference in either security target or certification report into `train/valid/test` splits in `30/20/50` fashion.
    - See [split](split/)
3. Choose all samples from test set, random 100 samples from train set and random 100 samples from validation set for manual annotations. Store those into [manual_annotations](manual_annotations/)
4. Label all references in [manual_annotations](manual_annotations/) as follows:
    - The reference meaning is recovered based on certification report and security target pdf.
    - The annotator should visit certification report first. If data in certification report is ambigous or does not allow precise annotation, the annotator should further visit the security target pdf.
    - The annotator should set `None` label on instances that he/she was unable to decide.
    - The annotator should label the `source` as:
        - `report` if he/she decided purely based on the data from certification report
        - `target` if he/she decided purely based on the data from security target
        - `report+target` if both artifacts were needed for resolution
        - Note that this label is only internal, not intended to be used for research
        - The label should be in lowercase letters with underscore, e.g., `evaluation_reused`.
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
