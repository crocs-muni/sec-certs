from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from setfit import SetFitModel

from sec_certs.utils.nlp import softmax

logger = logging.getLogger(__name__)


@dataclass
class ReferenceAnnotator:
    """
    Class for annotating references. Its instances are supposed to by trained by `ReferenceAnnotatorTrainer`.
    Can be serialized into a directory / load from a directory.
    """

    _model: Any
    _label_mapping: dict[int, str]
    _soft_voting_power: int = 2

    @classmethod
    def from_pretrained(cls, model_dir: str | Path) -> ReferenceAnnotator:
        """
        Loads classifier from directory, assuming that:
          - the SetFitModel was dumped into that directory with model.save_pretrained(model_dir)
          - json file label_mapping.json exists in model_dir

        :param str | Path model_dir: path to directory to search for model and label mapping
        :return RerefenceClassifier: classifier with SetFitModel and label mapping
        """
        logger.info(f"Loading pre-trained reference annotator from: {model_dir}")
        model = SetFitModel.from_pretrained(str(model_dir))
        with (Path(model_dir) / "label_mapping.json").open("r") as handle:
            label_mapping = json.load(handle)
            label_mapping = {int(k): v for k, v in label_mapping.items()}

        return cls(model, label_mapping)

    def save_pretrained(self, model_dir: str | Path):
        """
        Will dump _model and _label_mapping into a directory.
        """
        logger.info(f"Saving ReferenceAnnotator to {model_dir}")
        model_dir = Path(model_dir)
        model_dir.mkdir(exist_ok=True, parents=True)
        logger.info
        with (model_dir / "label_mapping.json").open("w") as handle:
            json.dump(self._label_mapping, handle, indent=4)
        self._model._save_pretrained(str(model_dir))

    def train(self, train_dataset: pd.DataFrame):
        raise NotImplementedError("ReferenceAnnotatorTrainer shall be used for training")

    def predict(self, X: list[list[str]]) -> list[str]:
        return [self._predict_single(x) for x in X]

    def _predict_single(self, sample: list[str]) -> str:
        # return self._predict_single_majority_vote(sample)
        return self._label_mapping[int(np.argmax(self._predict_proba_single(sample)))]

    def predict_proba(self, X: list[list[str]]) -> list[list[float]]:
        return [self._predict_proba_single(x) for x in X]

    def _predict_proba_single(self, sample: list[str]) -> list[float]:
        """
        1. Get predictions for each segment, convert pytorch tensor to numpy
        2. Square every prediction to reward confidence
        3. Sum probabilities for each label
        4. softmax
        """
        return softmax(np.power(self._model.predict_proba(sample, as_numpy=True), self._soft_voting_power).sum(axis=0))

    def _predict_single_majority_vote(self, sample: list[str]) -> str:
        predictions = self._model.predict(sample)
        most_common = Counter(predictions).most_common()
        if len(most_common) > 1 and most_common[0][1] == most_common[1][1]:
            return self._label_mapping[int(np.argmax(self._predict_proba_single(sample)))]
        else:
            return self._label_mapping[int(most_common[0][0])]

    def predict_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        WIll read df.segments and populate the dataframe with predictions.
        """
        df_new = df.copy()
        y_proba = self.predict_proba(df_new.segments)
        df_new["y_proba"] = y_proba
        df_new["y_pred"] = self.predict(df_new.segments)
        df_new["correct"] = df_new.apply(
            lambda row: row["y_pred"] == row["label"] if not pd.isnull(row["label"]) else np.NaN, axis=1
        )
        return df_new
