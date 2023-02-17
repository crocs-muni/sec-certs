import numpy as np
from sklearn.metrics import precision_score, recall_score


def prec_recall_metric(y_pred, y_true):
    return {
        "precision": precision_score(y_true, y_pred, zero_division="warn", average="micro"),
        "recall": recall_score(y_true, y_pred, zero_division="warn", average="micro"),
    }


def softmax(x):
    return np.exp(x - np.max(x)) / np.exp(x - np.max(x)).sum()
