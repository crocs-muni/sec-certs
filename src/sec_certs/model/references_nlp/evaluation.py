import logging
from pathlib import Path
from typing import Literal

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import plotly.express as px
from catboost import CatBoostClassifier
from sklearn.dummy import DummyClassifier
from sklearn.metrics import ConfusionMatrixDisplay, balanced_accuracy_score, classification_report

logger = logging.getLogger(__name__)


def evaluate_model(
    clf: DummyClassifier | CatBoostClassifier,
    x_eval: np.ndarray,
    y_eval: np.ndarray,
    feature_cols: list[str],
    output_path: Path | None = None,
):
    logger.info("Evaluating model.")
    y_pred = clf.predict(x_eval)

    print(classification_report(y_eval, y_pred))
    print(f"Balanced accuracy score: {balanced_accuracy_score(y_eval, y_pred)}")

    fig = ConfusionMatrixDisplay.from_predictions(
        y_eval,
        y_pred,
        xticks_rotation=90,
    )

    if output_path:
        report_dict = classification_report(y_eval, y_pred, output_dict=True)
        report_df = pd.DataFrame(report_dict).transpose()
        report_df.to_csv(output_path / "classification_report.csv")
        fig.figure_.savefig(output_path / "confusion_matrix.png", bbox_inches="tight")
        with Path(output_path / "balanced_accuracy_score.txt").open("w") as handle:
            handle.write(str(balanced_accuracy_score(y_eval, y_pred)))

    if isinstance(clf, CatBoostClassifier):
        feature_importance = clf.get_feature_importance()
        sorted_idx = np.argsort(feature_importance)
        features = np.array(feature_cols)[sorted_idx]

        fig_feature_importance = plt.figure(figsize=(10, 12))
        plt.barh(features, feature_importance[sorted_idx], align="center")
        plt.xlabel("Feature Importance")
        plt.ylabel("Feature")
        plt.title("Feature Importance in Gradient boosted trees classifier")
        plt.tight_layout()
        plt.show()

        if output_path:
            fig_feature_importance.savefig(output_path / "feature_importance.png")


def display_dim_red_scatter(df: pd.DataFrame, dim_red: Literal["umap", "pca"]) -> None:
    df_exploded = df.explode(["segments", dim_red]).reset_index()

    x_col = dim_red + "_x"
    y_col = dim_red + "_y"

    df_exploded[x_col] = df_exploded[dim_red].map(lambda x: x[0])
    df_exploded[y_col] = df_exploded[dim_red].map(lambda x: x[1])
    df_exploded["wrapped_segment"] = df_exploded.segments.str.wrap(60).map(lambda x: x.replace("\n", "<br>"))

    fig = px.scatter(
        df_exploded,
        x=x_col,
        y=y_col,
        color="label",
        hover_data=["dgst", "canonical_reference_keyword", "wrapped_segment"],
        width=1500,
        height=1000,
        title=f"{dim_red.upper()} projection of segment embeddings.",
    )
    fig.show()
