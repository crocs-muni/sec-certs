from __future__ import annotations

from typing import Callable, Literal

import numpy as np
from datasets import Dataset
from sentence_transformers.losses import CosineSimilarityLoss
from setfit import SetFitModel, SetFitTrainer


class ReferenceClassifierTrainer:
    def __init__(
        self,
        train_dataset: Dataset,
        eval_dataset: Dataset,
        metric: Callable,
        mode: Literal["transformer", "baseline"] = "transformer",
    ):
        self._model, self._trainer = self._init_trainer(mode)
        self.clf = RerefenceClassifier(self._model, self.get_label_mapping())
        self._train_dataset = train_dataset
        self._eval_dataset = eval_dataset
        self._metric = metric

    def _init_trainer(self, mode: Literal["transformer", "baseline"]):
        return (
            self._init_transformer_model_and_trainer()
            if mode == "transformer"
            else self._init_baseline_model_and_trainer()
        )

    def _init_transformer_model_and_trainer(self):
        model = SetFitModel.from_pretrained("all-mpnet-base-v2")
        trainer = SetFitTrainer(
            model=model,
            train_dataset=self._train_dataset,
            eval_dataset=self._valid_dataset,
            loss_class=CosineSimilarityLoss,
            metric=self._metric,
            batch_size=16,
            num_iterations=40,  # The number of text pairs to generate for contrastive learning
            num_epochs=1,  # The number of epochs to use for contrastive learning
            column_mapping={
                "sentences": "text",
                "label": "label",
            },  # Map dataset columns to text/label expected by trainer
        )
        return model, trainer

    def _init_baseline_model_and_trainer(self):
        raise NotImplementedError("Not yet implemented.")

    def train(self):
        self._trainer.train(show_progress_bar=True)

    def evaluate(self):
        self._trainer.evaluate()

    def get_label_mapping(self) -> dict[int, str]:
        return {index: x for index, x in enumerate(self._train_dataset.features["label"].names)}


class BaselineTrainer:
    pass


class RerefenceClassifier:
    def __init__(self, model, label_mapping: dict[int, str]):
        self._model = model
        self._label_mapping = label_mapping

    def predict(self, X: list[list[str]]) -> list[str]:
        return [self._predict_single(x) for x in X]

    def _predict_single(self, sample: list[str]) -> str:
        """
        1. Get predictions for each sentence
        2. Square every prediction to reward confidence
        3. Sum probabilities for each label
        4. Map to label and return
        """
        preds = np.array(x for x in self._model.predict_proba(sample))
        preds = np.power(preds, 2)
        preds = preds.sum(axis=0)
        return self._label_mapping[int(np.argmax(preds))]
