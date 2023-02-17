from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal

import numpy as np
import pandas as pd
from datasets import ClassLabel, Dataset, Features, NamedSplit, Value
from sentence_transformers.losses import CosineSimilarityLoss
from setfit import SetFitModel, SetFitTrainer

from sec_certs.utils.nlp import softmax


class ReferenceClassifierTrainer:
    def __init__(
        self,
        train_dataset: pd.DataFrame,
        eval_dataset: pd.DataFrame,
        metric: Callable,
        mode: Literal["transformer", "baseline"] = "transformer",
    ):
        self._train_dataset = train_dataset
        self._validation_dataset = eval_dataset
        self._metric = metric
        self._model, self._trainer, self.label_mapping = self._init_trainer(mode)
        self.clf = RerefenceClassifier(self._model, self.label_mapping)

    def _init_trainer(self, mode: Literal["transformer", "baseline"]):
        return (
            self._init_transformer_model_and_trainer()
            if mode == "transformer"
            else self._init_baseline_model_and_trainer()
        )

    def _init_transformer_model_and_trainer(self):
        model = SetFitModel.from_pretrained("all-mpnet-base-v2")

        internal_train_dataset = self._get_hugging_face_datasets_from_df(self._train_dataset, "train")
        internal_validation_dataset = self._get_hugging_face_datasets_from_df(self._validation_dataset, "validation")

        trainer = SetFitTrainer(
            model=model,
            train_dataset=internal_train_dataset,
            eval_dataset=internal_validation_dataset,
            loss_class=CosineSimilarityLoss,
            metric=self._metric,
            batch_size=16,
            num_iterations=40,  # The number of text pairs to generate for contrastive learning
            num_epochs=1,  # The number of epochs to use for contrastive learning
            column_mapping={
                "sentence": "text",
                "label": "label",
            },  # Map dataset columns to text/label expected by trainer
        )
        label_mapping = {index: x for index, x in enumerate(internal_train_dataset.features["label"].names)}
        return model, trainer, label_mapping

    @staticmethod
    def _get_hugging_face_datasets_from_df(df: pd.DataFrame, split: NamedSplit) -> Dataset:
        df_to_use = df.explode("sentences").rename(columns={"sentences": "sentence"})
        features = Features(
            {
                "dgst": Value("string"),
                "cert_id": Value("string"),
                "sentence": Value("string"),
                "label": ClassLabel(names=list(df_to_use.label.unique())),
            }
        )
        return Dataset.from_pandas(df_to_use, features=features, split=split, preserve_index=False)

    def _init_baseline_model_and_trainer(self):
        # Process the datasets so that BaselineTrainer can work with them and init the trainer.
        raise NotImplementedError("Not yet implemented.")

    def train(self):
        self._trainer.train(show_progress_bar=True)

    def evaluate(self):
        print("Internal evaluation (of model working on individual sentences)")
        print(self._evaluate_raw())
        print("Actual evaluation after ensemble soft voting")
        print(self._evaluate_stacked())

    def _evaluate_raw(self):
        return self._trainer.evaluate()

    def _evaluate_stacked(self):
        y_pred = self.clf.predict(self._validation_dataset.sentences)
        y_true = self._validation_dataset.label
        return self._metric(y_pred, y_true)


# TODO: Implement me
class BaselineTrainer:
    """
    This is where baseline method shall be implemented. It should accept the classifier and fit it on train_dataset.
    It should then use eval_dataset to evaluate the classifier.
    """

    def __init__(self, model, train_dataset, eval_dataset, metric):
        pass

    def train(self):
        pass

    def evaluate(self):
        pass


@dataclass
class RerefenceClassifier:
    _model: Any
    _label_mapping: dict[int, str]

    def predict(self, X: list[list[str]]) -> list[str]:
        return [self._predict_single(x) for x in X]

    def _predict_single(self, sample: list[str]) -> str:
        return self._label_mapping[int(np.argmax(self._predict_proba_single(sample)))]

    def predict_proba(self, X: list[list[str]]) -> list[list[float]]:
        return [self._predict_proba_single(x) for x in X]

    def _predict_proba_single(self, sample: list[str]) -> list[float]:
        """
        1. Get predictions for each sentence
        2. Square every prediction to reward confidence
        3. Sum probabilities for each label
        """
        return softmax(np.power(self._model.predict_proba(sample), 2).sum(axis=0))
