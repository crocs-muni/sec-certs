import json
from pathlib import Path
import logging
from typing import List, Set,Union

import numpy as np

logger = logging.getLogger(__name__)


def get_validation_dgsts(filepath: Union[str, Path]) -> Set[str]:
    with Path(filepath).open('r') as handle:
        data = json.load(handle)
    return set(data.keys())


def compute_precision(y: np.array, y_pred: np.array, **kwargs):
    prec = []
    for true, pred in zip(y, y_pred):
        set_pred = set(pred) if pred else set()
        set_true = set(true) if true else set()
        if set_pred and not set_true:
            prec.append(0)
        elif not set_true and not set_pred:
            prec.append(1)
        else:
            prec.append(len(set_true.intersection(set_pred)) / len(set_true))
    return np.mean(prec)
