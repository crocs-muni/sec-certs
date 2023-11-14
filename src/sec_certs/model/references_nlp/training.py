import logging
import os

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier, Pool
from sklearn.dummy import DummyClassifier
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import KFold

from sec_certs.constants import RANDOM_STATE, REF_ANNOTATION_MODES
from sec_certs.model.references_nlp.feature_extraction import get_data_for_clf

logger = logging.getLogger(__name__)


def _train_model(x_train, y_train, x_eval, y_eval, learning_rate: float = 0.03, depth: int = 6, l2_leaf_reg: int = 3):
    clf = CatBoostClassifier(
        learning_rate=learning_rate,
        depth=depth,
        l2_leaf_reg=l2_leaf_reg,
        task_type="GPU",
        devices=os.environ["CUDA_VISIBLE_DEVICES"],
        random_seed=RANDOM_STATE,
    )

    train_pool = Pool(x_train, y_train)
    eval_pool = Pool(x_eval, y_eval)
    clf.fit(train_pool, eval_set=eval_pool, verbose=False, plot=True, early_stopping_rounds=100, use_best_model=True)
    return clf


def train_model(
    df: pd.DataFrame,
    mode: REF_ANNOTATION_MODES,
    train_baseline: bool = False,
    use_pca: bool = True,
    use_umap: bool = True,
    use_lang: bool = True,
    use_pred: bool = True,
    learning_rate: float = 0.03,
    depth: int = 6,
    l2_leaf_reg: int = 3,
) -> tuple[DummyClassifier | CatBoostClassifier, pd.DataFrame, list[str]]:
    logger.info(f"Training model for mode {mode}")
    X_train, y_train, eval_df, feature_cols = get_data_for_clf(df, mode, use_pca, use_umap, use_lang, use_pred)
    if train_baseline:
        clf = DummyClassifier(random_state=RANDOM_STATE)
        clf.fit(X_train, y_train)
    else:
        assert eval_df is not None
        clf = _train_model(X_train, y_train, eval_df[feature_cols], eval_df.label, learning_rate, depth, l2_leaf_reg)

    return clf, eval_df, feature_cols


def cross_validate_model(df: pd.DataFrame, learning_rate: float = 0.03, depth: int = 6, l2_leaf_reg: int = 3) -> float:
    logger.info("Cross-validating model")
    X_train, y_train, _, _ = get_data_for_clf(df, "cross-validation", True, True, True, True)
    kf = KFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    scores = []
    for train_index, test_index in kf.split(X_train):
        X_train_, X_test_ = X_train[train_index], X_train[test_index]
        y_train_, y_test_ = y_train[train_index], y_train[test_index]
        clf = _train_model(X_train_, y_train_, X_test_, y_test_, learning_rate, depth, l2_leaf_reg)
        scores.append(balanced_accuracy_score(y_test_, clf.predict(X_test_)))

    return np.mean(scores)
