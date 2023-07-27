from __future__ import annotations

import logging
from typing import Callable, Literal

import pandas as pd
from datasets import ClassLabel, Dataset, Features, NamedSplit, Value
from sentence_transformers.losses import CosineSimilarityLoss
from setfit import SetFitModel, SetFitTrainer

from sec_certs.model.references.annotator import ReferenceAnnotator
from sec_certs.utils.nlp import prepare_reference_annotations_df

logger = logging.getLogger(__name__)


class ReferenceAnnotatorTrainer:
    def __init__(
        self,
        train_dataset: pd.DataFrame,
        eval_dataset: pd.DataFrame,
        metric: Callable,
    ):
        self._train_dataset = train_dataset
        self._eval_dataset = eval_dataset
        self._metric = metric
        self._model, self._trainer, self.label_mapping = self._init_trainer()
        self.clf = ReferenceAnnotator(self._model, self.label_mapping)

    @classmethod
    def from_df(
        cls,
        df: pd.DataFrame,
        metric: Callable,
        mode: Literal["training", "production"] = "training",
    ):
        df = prepare_reference_annotations_df(df)
        dataset_generation_method = {
            "training": ReferenceAnnotatorTrainer.split_df_for_training,
            "production": ReferenceAnnotatorTrainer.split_df_for_production,
        }

        train_dataset, eval_dataset = dataset_generation_method[mode](df)
        return cls(train_dataset, eval_dataset, metric)

    @staticmethod
    def split_df_for_training(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        return df.loc[df.split == "train"].drop(columns="split"), df.loc[df.split == "valid"].drop(columns="split")

    @staticmethod
    def split_df_for_production(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
        df.split = df.split.map({"test": "test", "train": "train", "valid": "train"})
        if df.loc[df.split == "test"].empty:
            logger.warning("`test` split for annotator dataset is empty -> model can be trained, but not evaluated.")
        return df.loc[df.split == "train"].drop(columns="split"), df.loc[df.split == "test"].drop(columns="split")

    def _init_trainer(self):
        # model = SetFitModel.from_pretrained("paraphrase-multilingual-mpnet-base-v2")
        model = SetFitModel.from_pretrained("all-mpnet-base-v2")

        internal_train_dataset = self._get_hugging_face_datasets_from_df(self._train_dataset, "train")
        internal_validation_dataset = self._get_hugging_face_datasets_from_df(self._eval_dataset, "validation")

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
                "segment": "text",
                "label": "label",
            },  # Map dataset columns to text/label expected by trainer
        )
        label_mapping = {index: x for index, x in enumerate(internal_train_dataset.features["label"].names)}
        return model, trainer, label_mapping

    @staticmethod
    def _get_hugging_face_datasets_from_df(df: pd.DataFrame, split: NamedSplit) -> Dataset:
        df_to_use = df.explode("segments").rename(columns={"segments": "segment"})
        features = Features(
            {
                "dgst": Value("string"),
                "referenced_cert_id": Value("string"),
                "segment": Value("string"),
                "label": ClassLabel(names=list(df_to_use.label.unique())),
            }
        )
        return Dataset.from_pandas(df_to_use, features=features, split=split, preserve_index=False)

    def train(self):
        self._trainer.train(show_progress_bar=True)

    def evaluate(self):
        print("Internal evaluation (of model working on individual segments)")
        print(self._evaluate_raw())
        print("Actual evaluation after ensemble soft voting")
        print(self._evaluate_stacked())

    def _evaluate_raw(self):
        if self._eval_dataset.empty:
            logger.error("Evaluation dataset is empty, cannot evaluate, returning.")
            return
        return self._trainer.evaluate()

    def _evaluate_stacked(self):
        y_pred = self.clf.predict(self._eval_dataset.segments)
        y_true = self._eval_dataset.label
        return self._metric(y_pred, y_true)
