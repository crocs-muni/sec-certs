"""
Simple script to perform hyperparameter search over various parameters of SentenceTransformer trained for reference
meaning classification.
"""

from __future__ import annotations

import os
from functools import partial
from pathlib import Path

import click
import optuna
import pandas as pd
import torch
from rapidfuzz import fuzz
from sklearn.metrics import f1_score

from sec_certs.dataset import CCDataset
from sec_certs.model.references.annotator_trainer import ReferenceAnnotatorTrainer
from sec_certs.model.references.segment_extractor import ReferenceSegmentExtractor
from sec_certs.utils.helpers import compute_heuristics_version
from sec_certs.utils.nlp import prec_recall_metric


def replace_all(text: str, to_replce: set[str]) -> str:
    for i in to_replce:
        text = text.replace(i, "")
    return text


def load_dataset(dataset_path: Path, annotations_dir: Path) -> tuple[CCDataset, pd.DataFrame]:
    """
    Load dataset from dataset_path and annotations_dir
    :param dataset_path: path to dataset
    :param annotations_dir: path to annotations
    :return: pd.DataFrame
    """
    train_annotations = pd.read_csv(annotations_dir / "train.csv")
    valid_annotations = pd.read_csv(annotations_dir / "valid.csv")
    all_annotations = pd.concat([train_annotations, valid_annotations])
    all_annotations = all_annotations[all_annotations.label != "None"].assign(label=lambda df: df.label.str.upper())

    dset = CCDataset.from_json(dataset_path)
    all_certs = {x.dgst: x for x in dset.certs.values()}
    dset.certs = {x.dgst: x for x in dset.certs.values() if x.dgst in all_annotations.dgst.unique()}

    cert_id_to_name_mapping = {x.heuristics.cert_id: x.name for x in all_certs.values()}
    all_annotations["referenced_cert_name"] = all_annotations["referenced_cert_id"].map(cert_id_to_name_mapping)
    all_annotations["cert_name"] = all_annotations["dgst"].map(lambda x: dset[x].name)
    all_annotations["cert_versions"] = all_annotations["cert_name"].map(compute_heuristics_version)
    all_annotations = all_annotations.loc[all_annotations["referenced_cert_name"].notnull()].copy()
    all_annotations["referenced_cert_versions"] = all_annotations["referenced_cert_name"].map(
        compute_heuristics_version
    )
    all_annotations["cert_name_stripped_version"] = all_annotations.apply(
        lambda x: replace_all(x["cert_name"], x["cert_versions"]), axis=1
    )
    all_annotations["referenced_cert_name_stripped_version"] = all_annotations.apply(
        lambda x: replace_all(x["referenced_cert_name"], x["referenced_cert_versions"]), axis=1
    )
    all_annotations["name_similarity"] = all_annotations.apply(
        lambda x: fuzz.token_set_ratio(x["cert_name"], x["referenced_cert_name"]), axis=1
    )
    all_annotations["name_similarity_stripped_version"] = all_annotations.apply(
        lambda x: fuzz.token_set_ratio(x["cert_name_stripped_version"], x["referenced_cert_name_stripped_version"]),
        axis=1,
    )
    all_annotations["name_len_diff"] = all_annotations.apply(
        lambda x: abs(len(x["cert_name_stripped_version"]) - len(x["referenced_cert_name_stripped_version"])), axis=1
    )

    return dset, all_annotations


def preprocess_data(dset: CCDataset, df: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess data
    :param df: pd.DataFrame
    :return: pd.DataFrame
    """

    def process_segment(segment: str, referenced_cert_id: str) -> str:
        segment = segment.replace(referenced_cert_id, "the referenced product")
        return segment

    new_df = ReferenceSegmentExtractor()(dset.certs.values())
    new_df = new_df.loc[new_df.label.notnull()].copy()
    new_df = new_df.merge(
        df.loc[
            :,
            [
                "dgst",
                "referenced_cert_id",
                "name_similarity_stripped_version",
                "name_len_diff",
                "cert_name",
                "referenced_cert_name",
            ],
        ],
        on=["dgst", "referenced_cert_id"],
    )

    new_df.segments = new_df.apply(
        lambda row: [process_segment(x, row.referenced_cert_id) for x in row.segments], axis=1
    )

    return new_df


def define_trainer(trial: optuna.trial.Trial, df: pd.DataFrame) -> ReferenceAnnotatorTrainer:
    use_analytical_rule_name_similarity = trial.suggest_categorical(
        "use_analytical_rule_name_similarity", [True, False]
    )
    n_iterations = trial.suggest_int("n_iterations", 1, 50)
    n_epochs = trial.suggest_int("n_epochs", 1, 5)
    batch_size = trial.suggest_int("batch_size", 8, 32)
    segmenter_metric = trial.suggest_categorical("segmenter_metric", ["accuracy", "f1"])
    ensemble_soft_voting_power = trial.suggest_int("ensemble_soft_voting_power", 1, 5)

    return ReferenceAnnotatorTrainer.from_df(
        df,
        prec_recall_metric,
        mode="training",
        use_analytical_rule_name_similarity=use_analytical_rule_name_similarity,
        n_iterations=n_iterations,
        n_epochs=n_epochs,
        batch_size=batch_size,
        segmenter_metric=segmenter_metric,
        ensemble_soft_voting_power=ensemble_soft_voting_power,
    )


def objective(trial: optuna.trial.Trial, df: pd.DataFrame):
    trainer = define_trainer(trial, df)
    trainer.train()

    annotator = trainer.clf
    df_predicted = annotator.predict_df(df)

    return f1_score(
        df_predicted.loc[df_predicted.split == "valid", ["y_pred"]],
        df_predicted.loc[df_predicted.split == "valid", ["label"]],
        zero_division="warn",
        average="weighted",
    )


@click.command()
@click.option("-n", "--trials", "trials", type=int, required=True, help="Number of optimization trials to run.")
@click.option(
    "-d",
    "--dataset",
    "dataset_path",
    type=click.Path(exists=True, dir_okay=False, file_okay=True, readable=True),
    required=True,
    help="Path to CCDataset json.",
)
@click.option(
    "-a",
    "--annotations",
    "annotations_dir",
    type=click.Path(exists=True, dir_okay=True, file_okay=False, readable=True),
    required=True,
    help="Path to annotations directory.",
)
@click.option(
    "-o",
    "--output",
    "output_dir",
    type=click.Path(exists=True, dir_okay=True, file_okay=False, readable=True),
    required=True,
    help="Path to output directory.",
)
@click.option("-t", "--timeout", "timeout", type=int, default=24, help="Timeout in hours", show_default=True)
def main(trials: int, dataset_path: Path, annotations_dir: Path, output_dir: Path, timeout: int):
    if not torch.cuda.is_available():
        print("GPU is not available, exiting. Did you set `CUDA_VISIBLE_DEVICES` environment variable properly?")
        return -1

    if os.environ.get("TOKENIZERS_PARALLELISM", True) != "FALSE":
        print(
            "Tokenizers parallelism not disabled for spacy, exiting. Did you set `TOKENIZERS_PARALLELISM` environment variable to `FALSE`?"
        )
        return -1

    # os.environ["CUDA_VISIBLE_DEVICES"] = "MIG-56c53afb-6f08-5e5b-83fa-32fc6f09eeb0"
    # os.environ["TOKENIZERS_PARALLELISM"] = "FALSE"

    dataset_path = Path(dataset_path)
    annotations_dir = Path(annotations_dir)
    output_dir = Path(output_dir)

    print("Loading dataset...")
    cc_dset, df = load_dataset(dataset_path, annotations_dir)

    print("Preprocessing data...")
    df_processed = preprocess_data(cc_dset, df)
    partial_objective = partial(objective, df=df_processed)

    print("Starting hyperparameter search...")
    study = optuna.create_study(direction="maximize")
    study.optimize(partial_objective, n_trials=trials, timeout=60 * 60 * timeout)

    study.trials_dataframe().to_csv(output_dir / "hyperparameter_search.csv")

    ax = optuna.visualization.matplotlib.plot_optimization_history(study)
    ax.figure.savefig(output_dir / "optimization_history.pdf", bbox_inches="tight")

    ax = optuna.visualization.matplotlib.plot_param_importances(study)
    ax.figure.savefig(output_dir / "param_importances.pdf", bbox_inches="tight")

    ax = optuna.visualization.matplotlib.plot_timeline(study)
    ax.figure.savefig(output_dir / "timeline.pdf", bbox_inches="tight")

    print("Done.")


if __name__ == "__main__":
    main()
