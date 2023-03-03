from __future__ import annotations

from ast import literal_eval

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score


def prec_recall_metric(y_pred, y_true):
    return {
        "precision": precision_score(y_true, y_pred, zero_division="warn", average="micro"),
        "recall": recall_score(y_true, y_pred, zero_division="warn", average="micro"),
    }


def softmax(x):
    return np.exp(x - np.max(x)) / np.exp(x - np.max(x)).sum()


def eval_strings(series):
    return [list(literal_eval(x)) for x in series]


def filter_short_sentences(sentences, cert_id):
    return [x for x in sentences if len(x) > len(cert_id) + 20]


def prepare_reference_annotations_df(df: pd.DataFrame):
    df = (
        df.loc[lambda df_: (df_.label != "SELF") & (df_.label.notnull())]
        .assign(segments=lambda df_: eval_strings(df_.segments))
        .drop(columns="lang")
    )
    df.segments = df.apply(lambda row: filter_short_sentences(row["segments"], row["referenced_cert_id"]), axis=1)
    df = df.loc[lambda df_: df_.segments.map(len) > 0]
    return df
