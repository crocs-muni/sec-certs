from __future__ import annotations

import logging
from functools import partial
from typing import Callable, Literal

import pandas as pd
from datasets import ClassLabel, Dataset, Features, NamedSplit, Value
from sentence_transformers.losses import CosineSimilarityLoss
from setfit import SetFitModel, SetFitTrainer
from sklearn.metrics import f1_score

from sec_certs.model.references.annotator import ReferenceAnnotator
from sec_certs.utils.nlp import prepare_reference_annotations_df

logger = logging.getLogger(__name__)


class ReferenceAnnotatorTrainer:
    def __init__(
        self,
        train_dataset: pd.DataFrame,
        eval_dataset: pd.DataFrame,
        metric: Callable,
        use_analytical_rule_name_similarity: bool = True,
        n_iterations: int = 20,
        n_epochs: int = 1,
        batch_size: int = 16,
        segmenter_metric: Literal["accuracy", "f1"] = "accuracy",
        ensemble_soft_voting_power: int = 2,
    ):
        self._train_dataset = train_dataset
        self._eval_dataset = eval_dataset
        self._metric = metric
        self.use_analytical_rule_name_similarity = use_analytical_rule_name_similarity
        self.n_iterations = n_iterations
        self.n_epochs = n_epochs
        self.batch_size = batch_size
        self.segmenter_metric = segmenter_metric
        self.ensemble_soft_voting_power = ensemble_soft_voting_power

        self._model, self._trainer, self.label_mapping = self._init_trainer()

        self.clf = ReferenceAnnotator(
            self._model, self.label_mapping, self.ensemble_soft_voting_power, self.use_analytical_rule_name_similarity
        )

    @classmethod
    def from_df(
        cls,
        df: pd.DataFrame,
        metric: Callable,
        mode: Literal["training", "production"] = "training",
        use_analytical_rule_name_similarity: bool = True,
        n_iterations: int = 20,
        n_epochs: int = 1,
        batch_size: int = 16,
        segmenter_metric: Literal["accuracy", "f1"] = "accuracy",
        ensemble_soft_voting_power: int = 2,
    ):
        df = prepare_reference_annotations_df(df)
        dataset_generation_method = {
            "training": ReferenceAnnotatorTrainer.split_df_for_training,
            "production": ReferenceAnnotatorTrainer.split_df_for_production,
        }

        train_dataset, eval_dataset = dataset_generation_method[mode](df)
        return cls(
            train_dataset,
            eval_dataset,
            metric,
            use_analytical_rule_name_similarity,
            n_iterations,
            n_epochs,
            batch_size,
            segmenter_metric,
            ensemble_soft_voting_power,
        )

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
        model = SetFitModel.from_pretrained("paraphrase-multilingual-mpnet-base-v2")
        # model = SetFitModel.from_pretrained("all-mpnet-base-v2")

        train_dataset_relevant_cols = self._train_dataset[["dgst", "referenced_cert_id", "segments", "label"]]
        eval_dataset_relevant_cols = self._eval_dataset[["dgst", "referenced_cert_id", "segments", "label"]]
        internal_train_dataset = self._get_hugging_face_datasets_from_df(train_dataset_relevant_cols, "train")
        internal_validation_dataset = self._get_hugging_face_datasets_from_df(eval_dataset_relevant_cols, "validation")

        # Align labels alphabetically
        labels_alphabetically = sorted(internal_train_dataset.features["label"].names)
        label2id = {label: index for index, label in enumerate(labels_alphabetically)}
        internal_train_dataset = internal_train_dataset.align_labels_with_mapping(label2id, "label")
        internal_validation_dataset = internal_validation_dataset.align_labels_with_mapping(label2id, "label")

        if self.segmenter_metric == "accuracy":
            metric_to_use = "accuracy"
        else:
            metric_to_use = partial(f1_score, average="weighted", zero_division=0)

        trainer = SetFitTrainer(
            model=model,
            train_dataset=internal_train_dataset,
            eval_dataset=internal_validation_dataset,
            loss_class=CosineSimilarityLoss,
            metric=metric_to_use,
            batch_size=self.batch_size,
            num_iterations=self.n_iterations,  # The number of text pairs to generate for contrastive learning
            num_epochs=self.n_epochs,  # The number of epochs to use for contrastive learning
            column_mapping={
                "segment": "text",
                "label": "label",
            },  # Map dataset columns to text/label expected by trainer
        )
        return model, trainer, {index: label for label, index in label2id.items()}

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
