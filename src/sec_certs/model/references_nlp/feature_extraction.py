import itertools
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Literal

import numpy as np
import pandas as pd
import spacy
import umap
import umap.plot
from rapidfuzz import fuzz
from scipy.spatial import ConvexHull, QhullError, distance_matrix
from scipy.stats import kurtosis, skew
from sklearn.decomposition import PCA
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder, StandardScaler

from sec_certs.constants import RANDOM_STATE, REF_ANNOTATION_MODES, REF_EMBEDDING_METHOD
from sec_certs.dataset import CCDataset
from sec_certs.model.references_nlp.annotator import ReferenceAnnotator
from sec_certs.model.references_nlp.annotator_trainer import ReferenceAnnotatorTrainer
from sec_certs.model.references_nlp.segment_extractor import ReferenceSegmentExtractor
from sec_certs.utils.nlp import prec_recall_metric

logger = logging.getLogger(__name__)

nlp = spacy.load("en_core_web_sm")


def strip_all(text: str, to_strip) -> str:
    if pd.isna(to_strip):
        return text
    for i in to_strip:
        text = text.replace(i, "")
    return text


def matches_recertification(segments: list[str]) -> bool:
    regex_a = r"This is a re-?\s?certification based on (the\s){0,1}REFERENCED_CERTIFICATE_ID"
    regex_b = r"Re-?\s?Zertifizierung basierend auf (the\s){0,1}REFERENCED_CERTIFICATE_ID"
    return any(
        re.search(regex_a, segment, re.IGNORECASE) or re.search(regex_b, segment, re.IGNORECASE) for segment in segments
    )


def compute_ngram_overlap_spacy(string1, string2, n):
    doc1 = nlp(string1)
    doc2 = nlp(string2)

    ngrams1 = [" ".join([token.text for token in doc1[i : i + n]]) for i in range(len(doc1) - n + 1)]
    ngrams2 = [" ".join([token.text for token in doc2[i : i + n]]) for i in range(len(doc2) - n + 1)]

    overlap = sum((Counter(ngrams1) & Counter(ngrams2)).values())
    return overlap


def compute_character_ngram_overlap(str1, str2, n):
    ngrams1 = [str1[i : i + n] for i in range(len(str1) - n + 1)]
    ngrams2 = [str2[i : i + n] for i in range(len(str2) - n + 1)]
    overlap = sum((Counter(ngrams1) & Counter(ngrams2)).values())
    return overlap


def compute_common_length(str1, str2, prefix=True):
    length = 0
    min_length = min(len(str1), len(str2))
    if prefix:
        for i in range(min_length):
            if str1[i] == str2[i]:
                length += 1
            else:
                break
    else:
        for i in range(1, min_length + 1):
            if str1[-i] == str2[-i]:
                length += 1
            else:
                break
    return length


def compute_numeric_token_overlap(str1, str2):
    doc1 = nlp(str1)
    doc2 = nlp(str2)

    tokens1 = [token.text for token in doc1 if token.like_num]
    tokens2 = [token.text for token in doc2 if token.like_num]

    overlap = sum((Counter(tokens1) & Counter(tokens2)).values())
    return overlap


def get_lang_features(base_name: str, referenced_name: str) -> tuple:
    common_numeric_words = compute_numeric_token_overlap(base_name, referenced_name)
    common_words = compute_ngram_overlap_spacy(base_name, referenced_name, 1)
    bigram_overlap = compute_ngram_overlap_spacy(base_name, referenced_name, 2)
    trigram_overlap = compute_ngram_overlap_spacy(base_name, referenced_name, 3)
    common_prefix_len = compute_common_length(base_name, referenced_name, True)
    common_suffix_len = compute_common_length(base_name, referenced_name, False)
    character_bigram_overlap = compute_character_ngram_overlap(base_name, referenced_name, 2)
    character_trigram_overlap = compute_character_ngram_overlap(base_name, referenced_name, 3)
    base_len = len(base_name)
    referenced_len = len(referenced_name)
    len_difference = abs(base_len - referenced_len)

    return (
        common_numeric_words,
        common_words,
        bigram_overlap,
        trigram_overlap,
        common_prefix_len,
        common_suffix_len,
        character_bigram_overlap,
        character_trigram_overlap,
        base_len,
        referenced_len,
        len_difference,
    )


def extract_segments(
    cc_dset: CCDataset,
    mode: REF_ANNOTATION_MODES,
    n_sents_before: int = 2,
    n_sents_after: int = 1,
) -> pd.DataFrame:
    logger.info("Extracting segments.")
    df = ReferenceSegmentExtractor(n_sents_before, n_sents_after)(list(cc_dset.certs.values()))
    if mode == "training":
        return df.loc[(df.label.notnull()) & ((df.split == "train") | (df.split == "valid"))]
    elif mode == "evaluation":
        return df.loc[df.label.notnull()]
    elif mode == "production":
        return df
    else:
        raise ValueError(f"Unknown mode {mode}")


def _build_transformer_embeddings(
    segments: pd.DataFrame, mode: REF_ANNOTATION_MODES, model_path: Path | None = None
) -> tuple[pd.DataFrame, ReferenceAnnotator]:
    should_save_model = model_path is not None
    annotator = None
    logger.info("Building transformer embeddings.")
    if model_path:
        try:
            annotator = ReferenceAnnotator.from_pretrained(model_path)
            should_save_model = False
        except Exception:
            print(f"Failed to load ReferenceAnnotator from {model_path}.")
            should_save_model = True

    if not annotator:
        print("Training ReferenceAnnotator from scratch.")
        trainer = ReferenceAnnotatorTrainer.from_df(
            segments,
            prec_recall_metric,
            mode=mode,
            n_iterations=8,
            n_epochs=2,
            learning_rate=1.23e-5,
            batch_size=16,
            segmenter_metric="balanced_accuracy",
            ensemble_soft_voting_power=2,
            show_progress_bar=False,
        )
        trainer.train()
        annotator = trainer.clf
    assert annotator is not None

    if should_save_model and model_path:
        annotator.save_pretrained(model_path)

    return (
        segments.copy().assign(embeddings=lambda df_: df_.segments.map(annotator._model.model_body.encode)),
        annotator,
    )


def _build_tf_idf_embeddings(segments: pd.DataFrame, mode: REF_ANNOTATION_MODES) -> pd.DataFrame:
    def choose_values_to_fit(df_: pd.DataFrame) -> list[str]:
        if mode == "training":
            return df_.loc[df_.split == "train"].copy().explode("segments").segments.values
        elif mode == "evaluation":
            return df_.loc[df_.split != "test"].copy().explode("segments").segments.values
        elif mode == "production":
            return df_.copy().explode("segments").segments.values
        else:
            raise ValueError(f"Unknown mode {mode}")

    logger.info("Building TF-IDF embeddings.")
    tf_idf = TfidfVectorizer()
    tf_idf = tf_idf.fit(choose_values_to_fit(segments))

    return segments.copy().assign(
        embeddings=lambda df_: df_.segments.map(lambda x: tf_idf.transform(x).toarray().tolist())
    )


def build_embeddings(
    segments: pd.DataFrame,
    mode: REF_ANNOTATION_MODES,
    method: REF_EMBEDDING_METHOD,
    model_path: Path | None = None,
) -> tuple[pd.DataFrame, ReferenceAnnotator | None]:
    if method == "transformer":
        return _build_transformer_embeddings(segments, mode, model_path)
    if method == "tf_idf":
        return _build_tf_idf_embeddings(segments, mode), None
    raise ValueError(f"Unknown embedding method {method}")


def extract_language_features(df: pd.DataFrame, cc_dset: CCDataset) -> pd.DataFrame:
    logger.info("Extracting language features.")
    certs = list(cc_dset.certs.values())
    dgst_to_cert_name = {x.dgst: x.name for x in certs}
    cert_id_to_cert_name = {x.heuristics.cert_id: x.name for x in certs}
    dgst_to_extracted_versions = {x.dgst: x.heuristics.extracted_versions for x in certs}
    cert_id_to_extracted_versions = {x.heuristics.cert_id: x.heuristics.extracted_versions for x in certs}

    df_lang = (
        df.copy()
        .assign(
            cert_name=lambda df_: df_.dgst.map(dgst_to_cert_name),
            referenced_cert_name=lambda df_: df_.canonical_reference_keyword.map(cert_id_to_cert_name),
            cert_versions=lambda df_: df_.dgst.map(dgst_to_extracted_versions),
            referenced_cert_versions=lambda df_: df_.canonical_reference_keyword.map(cert_id_to_extracted_versions),
            cert_name_stripped_version=lambda df_: df_.apply(
                lambda x: strip_all(x["cert_name"], x["cert_versions"]), axis=1
            ),
            referenced_cert_name_stripped_version=lambda df_: df_.apply(
                lambda x: strip_all(x["referenced_cert_name"], x["referenced_cert_versions"]),
                axis=1,
            ),
            lang_token_set_ratio=lambda df_: df_.apply(
                lambda x: fuzz.token_set_ratio(
                    x["cert_name_stripped_version"],
                    x["referenced_cert_name_stripped_version"],
                ),
                axis=1,
            ),
            lang_partial_ratio=lambda df_: df_.apply(
                lambda x: fuzz.partial_ratio(
                    x["cert_name_stripped_version"],
                    x["referenced_cert_name_stripped_version"],
                ),
                axis=1,
            ),
            lang_token_sort_ratio=lambda df_: df_.apply(
                lambda x: fuzz.token_sort_ratio(
                    x["cert_name_stripped_version"],
                    x["referenced_cert_name_stripped_version"],
                ),
                axis=1,
            ),
            lang_n_segments=lambda df_: df_.segments.map(lambda x: len(x) if x else 0),
            lang_matches_recertification=lambda df_: df_.segments.map(matches_recertification),
        )
        .assign(
            lang_n_extracted_versions=lambda df_: df_.cert_versions.map(lambda x: len(x) if x else 0),
            lang_n_intersection_versions=lambda df_: df_.apply(
                lambda x: len(set(x["cert_versions"]).intersection(set(x["referenced_cert_versions"]))),
                axis=1,
            ),
        )
    )

    df_lang_other_features = df_lang.apply(
        lambda row: get_lang_features(row["cert_name"], row["referenced_cert_name"]),
        axis=1,
    ).apply(pd.Series)
    lang_features = [
        "common_numeric_words",
        "common_words",
        "bigram_overlap",
        "trigram_overlap",
        "common_prefix_len",
        "common_suffix_len",
        "character_bigram_overlap",
        "character_trigram_overlap",
        "base_len",
        "referenced_len",
        "len_difference",
    ]
    df_lang_other_features.columns = ["lang_" + x for x in lang_features]

    df_lang = pd.concat([df_lang, df_lang_other_features], axis=1).assign(
        lang_should_not_be_component=lambda df_: df_.apply(
            lambda x: x.lang_len_difference < 5 and x.lang_token_set_ratio == 100,
            axis=1,
        ),
    )
    for col in df_lang.columns:
        if col.startswith("pred_"):
            df_lang[col] = df_lang[col] / df_lang.lang_n_segments

    return df_lang


def perform_dimensionality_reduction(
    df: pd.DataFrame,
    mode: REF_ANNOTATION_MODES,
    umap_n_neighbors: int = 10,
    umap_min_dist: float = 0.51026,
    umap_metric: Literal["cosine", "euclidean", "manhattan"] = "cosine",
) -> pd.DataFrame:
    def choose_values_to_fit(df_: pd.DataFrame):
        if mode == "training":
            return df_.loc[df_.split == "train"].copy().embeddings.values
        elif mode == "evaluation":
            return df_.loc[df_.split != "test"].copy().embeddings.values
        elif mode == "production":
            return df_.copy().embeddings.values
        else:
            raise ValueError(f"Unknown mode {mode}")

    def choose_labels_to_fit(df_: pd.DataFrame):
        if mode == "training":
            return df_.loc[df_.split == "train"].copy().label.values
        elif mode == "evaluation":
            return df_.loc[df_.split != "test"].copy().label.values
        elif mode == "production":
            return df_.copy().label.values
        else:
            raise ValueError(f"Unknown mode {mode}")

    logger.info("Performing dimensionality reduction.")
    df_exploded = df.copy().explode(["segments", "embeddings"]).reset_index(drop=True)
    label_encoder = LabelEncoder()

    embeddings_to_fit = np.vstack(choose_values_to_fit(df_exploded))
    labels_to_fit = label_encoder.fit_transform(choose_labels_to_fit(df_exploded))

    scaler = StandardScaler()
    embeddings_to_fit_scaled = scaler.fit_transform(embeddings_to_fit)

    # parallel UMAP not available with random state
    umapper = umap.UMAP(
        n_neighbors=umap_n_neighbors,
        min_dist=umap_min_dist,
        metric=umap_metric,
        random_state=RANDOM_STATE,
        n_jobs=1,
    ).fit(embeddings_to_fit, y=labels_to_fit)
    pca_mapper = PCA(n_components=2, random_state=RANDOM_STATE).fit(embeddings_to_fit_scaled, y=labels_to_fit)

    all_embeddings = np.vstack(df.embeddings.values)
    all_embeddings_scaled = scaler.transform(all_embeddings)

    df_exploded["umap"] = umapper.transform(all_embeddings).tolist()
    df_exploded["pca"] = pca_mapper.transform(all_embeddings_scaled).tolist()

    return (
        df_exploded.groupby(["dgst", "canonical_reference_keyword"])
        .agg(
            {
                "segments": lambda x: x.tolist(),
                "actual_reference_keywords": "first",
                "label": "first",
                "split": "first",
                "embeddings": lambda x: x.tolist(),
                "umap": lambda x: x.tolist(),
                "pca": lambda x: x.tolist(),
            }
        )
        .reset_index()
    )


def extract_prediction_features(df: pd.DataFrame, model) -> pd.DataFrame:
    def get_setfit_prediction_numbers(val):
        counter = Counter(val.tolist())
        return [counter[x] for x in range(len(all_labels))]

    logger.info("Extracting prediction features.")
    df["annotator_predictions"] = df.segments.map(lambda x: model.predict(x))
    all_labels = set(itertools.chain.from_iterable(x.tolist() for x in df.annotator_predictions.values))

    df_features_pred = df.annotator_predictions.apply(get_setfit_prediction_numbers).apply(pd.Series)
    feature_names = [f"pred_{x}" for x in range(len(all_labels))]
    df_features_pred.columns = feature_names
    return pd.concat([df, df_features_pred], axis=1)


def extract_geometrical_features(df: pd.DataFrame) -> pd.DataFrame:
    def extract_features(points):
        # Convert list of points to a numpy array
        points = np.array(points)
        xs = points[:, 0]
        ys = points[:, 1]

        # Basic Descriptive Statistics
        mean_x, mean_y = np.mean(xs), np.mean(ys)
        var_x, var_y = np.var(xs), np.var(ys)
        std_x, std_y = np.std(xs), np.std(ys)
        if len(points) > 1:
            skew_x, skew_y = skew(xs), skew(ys)
            kurt_x, kurt_y = kurtosis(xs), kurtosis(ys)
        else:
            skew_x, skew_y = 0, 0
            kurt_x, kurt_y = 0, 0

        # Spatial Spread
        range_x, range_y = np.ptp(xs), np.ptp(ys)
        cov_xy = np.cov(xs, ys)[0, 1] if len(points) > 1 else 0
        median_x, median_y = np.median(xs), np.median(ys)

        # Distance-based Features
        centroid = [mean_x, mean_y]
        distances_to_centroid = np.linalg.norm(points - centroid, axis=1) if len(points) > 1 else [0]
        mean_distance = np.mean(distances_to_centroid)
        max_distance = np.max(distances_to_centroid)
        min_distance = np.min(distances_to_centroid)
        std_distance = np.std(distances_to_centroid)
        max_min_distance = max_distance - min_distance

        sorted_points = points[np.argsort(distances_to_centroid)]
        total_distance = np.sum(np.linalg.norm(sorted_points[1:] - sorted_points[:-1], axis=1))

        # Geometric Features
        hull_area, hull_perimeter = (0, 0)
        if len(points) > 2:  # ConvexHull needs at least 3 points
            try:
                hull = ConvexHull(points)
                hull_area = hull.volume
                hull_perimeter = hull.area
            except QhullError:
                pass

        pairwise_distances = distance_matrix(points, points) if len(points) > 1 else np.array([[0]])
        mean_pairwise_distance = np.mean(pairwise_distances)
        max_pairwise_distance = np.max(pairwise_distances)

        if len(points) > 1:
            min_coords = np.min(points, axis=0)
            max_coords = np.max(points, axis=0)
            bounding_box_width = max_coords[0] - min_coords[0]
            bounding_box_height = max_coords[1] - min_coords[1]
            bounding_box_area = bounding_box_width * bounding_box_height

            aspect_ratio = bounding_box_width / bounding_box_height if bounding_box_height != 0 else 1
            point_density = len(points) / bounding_box_area
        else:
            aspect_ratio = 0
            point_density = 0

        # Gather all features into a list
        features = [
            mean_x,
            mean_y,
            var_x,
            var_y,
            std_x,
            std_y,
            skew_x,
            skew_y,
            kurt_x,
            kurt_y,
            range_x,
            range_y,
            cov_xy,
            median_x,
            median_y,
            mean_distance,
            max_distance,
            min_distance,
            max_min_distance,
            std_distance,
            total_distance,
            hull_area,
            hull_perimeter,
            mean_pairwise_distance,
            max_pairwise_distance,
            aspect_ratio,
            point_density,
        ]

        return features

    feature_names = [
        "mean_x",
        "mean_y",
        "var_x",
        "var_y",
        "std_x",
        "std_y",
        "skew_x",
        "skew_y",
        "kurt_x",
        "kurt_y",
        "range_x",
        "range_y",
        "cov_xy",
        "median_x",
        "median_y",
        "mean_distance_to_centroid",
        "max_distance_to_centroid",
        "min_distance_to_centroid",
        "max_min_distance_to_centroid",
        "std_distance_to_centroid",
        "total_distances_to_centroid",
        "hull_area",
        "hull_perimeter",
        "mean_pairwise_distance",
        "max_pairwise_distance",
        "aspect_ratio",
        "point_density",
    ]

    logger.info("Extracting geometrical features.")
    df_features_pca = df.pca.apply(extract_features).apply(pd.Series)
    feature_names_pca = ["pca_" + x for x in feature_names]
    df_features_pca.columns = feature_names_pca

    df_features_umap = df.umap.apply(extract_features).apply(pd.Series)
    feature_names_umap = ["umap_" + x for x in feature_names]
    df_features_umap.columns = feature_names_umap

    return pd.concat([df, df_features_pca, df_features_umap], axis=1)


def _choose_feature_columns(
    df: pd.DataFrame, use_pca: bool = True, use_umap: bool = True, use_lang: bool = True, use_pred: bool = True
) -> list[str]:
    feature_columns = []
    if not use_pca and not use_umap and not use_lang and not use_pred:
        raise ValueError("At least one of PCA, UMAP or language features must be used.")
    if use_pca:
        feature_columns.extend([x for x in df.columns if x.startswith("pca_")])
    if use_umap:
        feature_columns.extend([x for x in df.columns if x.startswith("umap_")])
    if use_lang:
        feature_columns.extend([x for x in df.columns if x.startswith("lang_")])
    if use_pred:
        feature_columns.extend([x for x in df.columns if x.startswith("pred_")])
    return feature_columns


def _split_df(df: pd.DataFrame, mode: REF_ANNOTATION_MODES) -> tuple[pd.DataFrame, pd.DataFrame | None]:
    if mode == "training":
        train_df = df.loc[df.split == "train"].copy()
        eval_df = df.loc[df.split == "valid"].copy()
    elif mode == "evaluation":
        train_df = df.loc[df.split != "test"].copy()
        eval_df = df.loc[df.split == "test"].copy()
    elif mode == "production":
        train_df = df.copy()
        eval_df = df.copy()
    elif mode == "cross-validation":
        train_df = df.loc[df.split != "test"].copy()
        eval_df = None
    else:
        raise ValueError(f"Unknown mode {mode}")
    return train_df, eval_df


def dataframe_to_training_arrays(
    df: pd.DataFrame,
    mode: REF_ANNOTATION_MODES,
    use_pca: bool = True,
    use_umap: bool = True,
    use_lang: bool = True,
    use_pred: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray | None, np.ndarray | None, list[str]]:
    feature_columns = _choose_feature_columns(df, use_pca, use_umap, use_lang, use_pred)
    train_df, eval_df = _split_df(df.loc[df.label.notnull()].copy(), mode)

    x_train, y_train = (
        np.vstack(train_df[feature_columns].values),
        train_df.label.values,
    )
    if eval_df is not None:
        x_valid, y_valid = (
            np.vstack(eval_df[feature_columns].values),
            eval_df.label.values,
        )
    else:
        x_valid, y_valid = None, None

    return (
        x_train,
        y_train,
        x_valid,
        y_valid,
        feature_columns,
    )
