from __future__ import annotations

import json
import logging
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
    _use_analytical_rule_name_similarity: bool = True

    # TODO: This does not load hyperparameters, only the model and label mapping
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

    # TODO: This does not save hyperparameters, only the model and label mapping
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

    def predict_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        WIll read df.segments and populate the dataframe with predictions.
        """
        df_new = df.copy()
        y_proba = self.predict_proba(df.segments)
        df_new["y_proba"] = y_proba
        df_new["y_pred"] = df_new.y_proba.map(lambda x: self._label_mapping[int(np.argmax(x))])

        if self._use_analytical_rule_name_similarity:
            df_new.loc[
                (df_new.name_similarity_stripped_version == 100)
                & (df_new.name_len_diff < 5)
                & ((df_new.y_pred != "RECERTIFICATION") & (df_new.y_pred != "PREVIOUS_VERSION")),
                ["y_pred"],
            ] = "PREVIOUS_VERSION"

        df_new["correct"] = df_new.apply(
            lambda row: row["y_pred"] == row["label"] if not pd.isnull(row["label"]) else np.NaN, axis=1
        )
        return df_new
