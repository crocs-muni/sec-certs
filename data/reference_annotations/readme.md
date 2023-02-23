# Reference annotations

This folder contains data and the methodology (presented below) related to learning the reference annotations.

- The folder [split](split) contains split of the CC Dataset to `train/valid/test` splits for learning.
- The csv file [manually_annotated_references.csv](./manually_annotated_references.csv) contains manually acquired labels to references obtained with the methodology outlined below.

### Reference taxonomy

After manually inspecting the certificates from [manually_annotated_references.csv](./manually_annotated_references.csv), we have identified the following reference meanings:

- **Component used**: The referenced certificate is a component used in the examined certificate (e.g., IC used by a smartcard). Some evaluation results were likely shared/re-used. This is a specific case of *evaluation reused* label
- **Component shared**: The referenced certificate shares some components with the examined certificate. Some evaluation results were likely shared/re-used. This is a specific case of *evaluation reused* label.
- **Evaluation reused**: The evaluation results of the referenced certificate were used for evaluation of the examined certificate, due to reasons that could not be resolved as *component used* nor *component shared*.
- **Recertification**: The examined certificate is a re-certification of the referenced certificate.
- **Previous version**: The product in the referenced certificate is a previous version of the product in the examined certificate and the recertification is not explicitly mentioned.
- **On platform**: The examined certificate runs on a platform that is certified in the referenced certificate.
