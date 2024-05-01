# Protocol of hyperparameter tunning for reference annotation task

We identified several steps of the hyperparameter tunning process with the following variables to finetune:

**1. Segment extractor**
- `n_sentences_before` -- number of sentences to take before each sentence that contains a reference
- `n_sentences_after` -- number of sentences to take after each sentence that contains a reference

**2. Embedding model**
- `n_epochs` -- number of epochs to train the model
- `learning_rate` -- learning rate of the model
- `n_iterations` -- number of iterations for contrastive learning
- `segmenter_metric` -- which metric to use for finetunning of the embeddings classifier (accuracy, F1 score)

**3. Dimensionality reduction**
- `n_neighbors` -- number of neighbors to use for UMAP dimensionality reduction
- `min_distance` -- minimum distance between points in the UMAP embedding
- `metric` -- distance metric to use for UMAP dimensionality reduction

**4. Boosted trees**
- `learning_rate` -- learning rate of the boosted trees model
- `tree_depth` -- depth of the boosted trees model
- `l2_leaf_reg` -- L2 regularization coefficient of the boosted trees model


## Notes

- Each of the steps was finetuned separately, using finetuned steps for the tasks that precede it, and using untuned steps for the tasks that come after the trained steps.
- The artifacts can be found in the resepctive folders, together with the scripts used to run the hyperparameter search.
- Optuna was used to suggest the hyperparameters, the value ranges can be read out from the scripts. Each of the steps run for 24 hours at most.
- Extractor yielded (4,4) as the best hyperparameter set. However, the same setting was used and produced much worse performance. The default setting (1,2) (after, before) was used instead, that produces more consitent results.
- The git revision used for finding the optimal set of parameters was: **Anonymized**
