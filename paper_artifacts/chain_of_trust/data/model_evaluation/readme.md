## Reference annotation evaluation

- Balanced accuracy was used to optimimize the hyperparameters of the reference annotation task.
- Note that the balanced accuracy is defined as an average of recall over all classes
- Two classification problems:
  - 5 classes
  - 2 classes
- Three variants for each of the problems:
  - Random (prior knowledge) baseline
  - TF-IDF for feature extraction, then all as normal
  - Embeddings for feature extraction
- The respective folders contain results for the individual variants.

