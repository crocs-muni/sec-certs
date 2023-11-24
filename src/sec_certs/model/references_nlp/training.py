import logging
import os

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier, Pool
from sklearn.dummy import DummyClassifier
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import KFold

from sec_certs.constants import RANDOM_STATE, REF_ANNOTATION_MODES
from sec_certs.model.references_nlp.feature_extraction import dataframe_to_training_arrays

logger = logging.getLogger(__name__)


def _train_model(
    mode: REF_ANNOTATION_MODES,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray | None = None,
    y_eval: np.ndarray | None = None,
    learning_rate: float = 0.03,
    depth: int = 6,
    l2_leaf_reg: float = 3,
):
    # In production mode, we don't have early stopping on validation set. Hence we use number of iterations that worked during evaluation.
    n_iters = 20 if mode == "production" else 1000
    clf = CatBoostClassifier(
        learning_rate=learning_rate,
        depth=depth,
        l2_leaf_reg=l2_leaf_reg,
        task_type="GPU",
        devices=os.environ["CUDA_VISIBLE_DEVICES"],
        random_seed=RANDOM_STATE,
        iterations=n_iters,
    )

    train_pool = Pool(x_train, y_train)
    eval_pool = Pool(x_eval, y_eval) if x_eval is not None else None
    clf.fit(
        train_pool,
        eval_set=eval_pool,
        verbose=False,
        plot=True,
        early_stopping_rounds=100,
        use_best_model=True,
    )
    return clf


def train_model(
    mode: REF_ANNOTATION_MODES,
    x_train: np.ndarray,
    y_train: np.ndarray,
    x_eval: np.ndarray | None = None,
    y_eval: np.ndarray | None = None,
    train_baseline: bool = False,
    learning_rate: float = 0.079573,
    depth: int = 10,
    l2_leaf_reg: float = 7.303517,
) -> DummyClassifier | CatBoostClassifier:
    logger.info(f"Training model with baselne={train_baseline}")

    if train_baseline:
        clf = DummyClassifier(random_state=RANDOM_STATE)
        clf.fit(x_train, y_train)
    else:
        clf = _train_model(
            mode,
            x_train,
            y_train,
            x_eval,
            y_eval,
            learning_rate,
            depth,
            l2_leaf_reg,
        )
    return clf


def cross_validate_model(
    mode: REF_ANNOTATION_MODES, df: pd.DataFrame, learning_rate: float = 0.03, depth: int = 6, l2_leaf_reg: int = 3
) -> float:
    logger.info("Cross-validating model")
    X_train, y_train, _, _, _ = dataframe_to_training_arrays(df, "cross-validation", True, True, True, True)
    kf = KFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    scores = []
    for train_index, test_index in kf.split(X_train):
        X_train_, X_test_ = X_train[train_index], X_train[test_index]
        y_train_, y_test_ = y_train[train_index], y_train[test_index]
        clf = _train_model(mode, X_train_, y_train_, X_test_, y_test_, learning_rate, depth, l2_leaf_reg)
        scores.append(balanced_accuracy_score(y_test_, clf.predict(X_test_)))

    return np.mean(scores)
