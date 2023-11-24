from __future__ import annotations

from ast import literal_eval

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score


def prec_recall_metric(y_pred, y_true):
    return {
        "precision": precision_score(y_true, y_pred, zero_division="warn", average="weighted"),
        "recall": recall_score(y_true, y_pred, zero_division="warn", average="weighted"),
    }


def softmax(x):
    return np.exp(x - np.max(x)) / np.exp(x - np.max(x)).sum()


def eval_strings_if_necessary(series: pd.Series) -> pd.Series:
    return series.map(literal_eval) if isinstance(series.iloc[0], str) else series


def filter_short_sentences(sentences, actual_reference_keywords):
    return [x for x in sentences if len(x) > min(len(x) for x in actual_reference_keywords) + 20]


def prepare_reference_annotations_df(df: pd.DataFrame):
    if df.loc[(df.label != "SELF") & (df.label.notnull())].empty:
        raise ValueError("No expert annotations found in the dataset of references.")
    df = df.loc[lambda df_: (df_.label != "SELF") & (df_.label.notnull())].assign(
        segments=lambda df_: eval_strings_if_necessary(df_.segments)
    )
    df.segments = df.apply(
        lambda row: filter_short_sentences(row["segments"], row["actual_reference_keywords"]), axis=1
    )
    df = df.loc[lambda df_: df_.segments.map(len) > 0]
    return df
