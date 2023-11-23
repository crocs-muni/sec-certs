from __future__ import annotations

import itertools
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

# import langdetect
import numpy as np
import pandas as pd
import spacy

from sec_certs.sample.cc import CCCertificate
from sec_certs.sample.cc_certificate_id import CertificateId
from sec_certs.utils import parallel_processing

nlp = spacy.load("en_core_web_sm")
logger = logging.getLogger(__name__)


def swap_and_filter_dict(dct: dict[str, Any], filter_to_keys: set[str]):
    new_dct: dict[str, set[str]] = {}
    for key, val in dct.items():
        if val in new_dct:
            new_dct[val].add(key)
        else:
            new_dct[val] = {key}

    return {key: frozenset(val) for key, val in new_dct.items() if key in filter_to_keys}


def fill_reference_segments(record: ReferenceRecord, n_sent_before: int = 2, n_sent_after: int = 1) -> ReferenceRecord:
    """
    Compute indices of the sentences containing the reference keyword, take their surrounding sentences and join them.
    """

    def compute_surroundings(hit_index: int, max_index: int, n_before: int, n_after: int):
        """
        Computes indices of sentences to join into a coherent paragraph based on their location in text.
        Ideally we would like to take (hit_index - n_before, hit_index + n_after), but we need to make sure
        that we do not go out of bounds.
        """
        lower = max(0, hit_index - n_before)
        upper = min(max_index, hit_index + n_after)
        return range(lower, upper + 1)

    with record.processed_data_source_path.open("r") as handle:
        data = handle.read()

    sents = [sent.text for sent in nlp(data).sents]
    indices_of_relevant_sents = [sents.index(x) for x in sents if any(y in x for y in record.actual_reference_keywords)]

    if not indices_of_relevant_sents:
        record.segments = None
        return record

    sequences_to_take = [
        compute_surroundings(x, len(sents) - 1, n_sent_before, n_sent_after) for x in indices_of_relevant_sents
    ]
    record.segments = {"".join([sents[y] for y in x]) for x in sequences_to_take}

    return record


def preprocess_data_source(record: ReferenceRecord) -> ReferenceRecord:
    # TODO: There's some space for improvement, the preprocessing is acutally run twice.

    with record.raw_data_source_path.open("r") as handle:
        data = handle.read()

    processed_data = preprocess_txt_func(data, record.actual_reference_keywords)

    with record.processed_data_source_path.open("w") as handle:
        handle.write(processed_data)

    return record


def find_bracket_pattern(sentences: set[str], actual_reference_keywords: frozenset[str]):
    patterns = [r"(\[.+?\])(?=.*" + x + r")" for x in actual_reference_keywords]
    res: list[tuple[str, str]] = []

    for sent in sentences:
        for pattern, keyword in zip(patterns, actual_reference_keywords):
            matches = re.findall(pattern, sent, flags=re.MULTILINE | re.UNICODE | re.DOTALL)
            if matches:
                res.append((matches[-1], keyword))
    return res


def preprocess_txt_func(data: str, actual_reference_keywords: frozenset[str]) -> str:
    data = replace_acronyms(data)
    data = replace_citation_identifiers(data, actual_reference_keywords)
    return data


def replace_citation_identifiers(data: str, actual_reference_keywords: frozenset[str]) -> str:
    segments = {sent.text for sent in nlp(data).sents if any(x in sent.text for x in actual_reference_keywords)}
    patterns_to_replace = find_bracket_pattern(segments, actual_reference_keywords)
    for x in patterns_to_replace:
        data = data.replace(x[0], x[1])
    return data


def replace_acronyms(text: str) -> str:
    acronym_replacements = {
        "TOE": "target of evaluation",
        "CC": "certification framework",
        "PP": "protection profile",
        "ST": "security target",
        "SFR": "security Functional Requirement",
        "SFRs": "security Functional Requirements",
        "IC": "integrated circuit",
        "MRTD": "machine readable travel document",
        "TSF": "security functions of target of evaluation",
        "PACE": "password authenticated connection establishment",
    }

    for acronym, replacement in acronym_replacements.items():
        pattern = rf"(?<!\S){re.escape(acronym)}(?!\S)"
        text = re.sub(pattern, replacement, text)

    return text


@dataclass
class ReferenceRecord:
    """
    Data structure to hold objects when extracting text segments from txt files relevant for reference annotations.
    """

    certificate_dgst: str
    raw_data_source_path: Path
    processed_data_source_path: Path
    canonical_reference_keyword: str
    actual_reference_keywords: frozenset[str]
    source: str
    segments: set[str] | None = None

    def to_pandas_tuple(self) -> tuple[str, str, frozenset[str], str, set[str] | None]:
        return (
            self.certificate_dgst,
            self.canonical_reference_keyword,
            self.actual_reference_keywords,
            self.source,
            self.segments,
        )


class ReferenceSegmentExtractor:
    """
    Class to process list of certificates into a dataframe that holds reference segments.
    Should be only called with ReferenceSegmentExtractor()(list_of_certificates)
    """

    def __init__(self, n_sents_before: int = 1, n_sents_after: int = 0):
        self.n_sents_before = n_sents_before
        self.n_sents_after = n_sents_after

    def __call__(self, certs: Iterable[CCCertificate]) -> pd.DataFrame:
        return self._prepare_df_from_cc_dset(certs)

    def _prepare_df_from_cc_dset(self, certs: Iterable[CCCertificate]) -> pd.DataFrame:
        """
        Prepares processed DataFrame for reference annotator training from a list of certificates. This method:
        - Extracts text segments relevant for each reference out of the certificates, forms dataframe from those
        - Loads data splits into train/valid/test (unseen certificates are put into test set)
        - Loads manually annotated samples
        - Combines all of that into single dataframe
        """
        target_certs = [x for x in certs if x.heuristics.st_references.directly_referencing and x.state.st_txt_path]
        report_certs = [
            x for x in certs if x.heuristics.report_references.directly_referencing and x.state.report_txt_path
        ]
        df_targets = self._build_df(target_certs, "target")
        df_reports = self._build_df(report_certs, "report")
        print(f"df_targets shape: {df_targets.shape}")
        print(f"df_reports shape: {df_reports.shape}")

        return ReferenceSegmentExtractor._process_df(pd.concat([df_targets, df_reports]), certs)

    def _build_records(self, certs: list[CCCertificate], source: Literal["target", "report"]) -> list[ReferenceRecord]:
        def get_cert_records(cert: CCCertificate, source: Literal["target", "report"]) -> list[ReferenceRecord]:
            canonical_ref_var = {
                "target": "st_references",
                "report": "report_references",
            }
            actual_ref_var = {"target": "st_keywords", "report": "report_keywords"}
            raw_source_var = {"target": "st_txt_path", "report": "report_txt_path"}

            canonical_references = getattr(cert.heuristics, canonical_ref_var[source]).directly_referencing
            actual_references = getattr(cert.pdf_data, actual_ref_var[source])["cc_cert_id"]
            actual_references = {
                inner_key: CertificateId(outer_key, inner_key).canonical
                for outer_key, val in actual_references.items()
                for inner_key in val
            }
            actual_references = swap_and_filter_dict(actual_references, canonical_references)

            raw_source_dir = getattr(cert.state, raw_source_var[source]).parent
            processed_source_dir = raw_source_dir.parent / "txt_processed"

            return [
                ReferenceRecord(
                    cert.dgst,
                    raw_source_dir / f"{cert.dgst}.txt",
                    processed_source_dir / f"{cert.dgst}.txt",
                    key,
                    val,
                    source,
                )
                for key, val in actual_references.items()
            ]

        (certs[0].state.report_txt_path.parent.parent / "txt_processed").mkdir(exist_ok=True, parents=True)
        (certs[0].state.st_txt_path.parent.parent / "txt_processed").mkdir(exist_ok=True, parents=True)
        return list(itertools.chain.from_iterable(get_cert_records(cert, source) for cert in certs))

    def _build_df(self, certs: list[CCCertificate], source: Literal["target", "report"]) -> pd.DataFrame:
        records = self._build_records(certs, source)

        records = parallel_processing.process_parallel(
            preprocess_data_source,
            records,
            use_threading=False,
            progress_bar=True,
            progress_bar_desc="Preprocessing data",
        )
        records_with_args = [(x, self.n_sents_before, self.n_sents_after) for x in records]

        results = parallel_processing.process_parallel(
            fill_reference_segments,
            records_with_args,
            unpack=True,
            use_threading=False,
            progress_bar=True,
            progress_bar_desc="Recovering reference segments",
        )

        print(f"I now have {len(results)} in {source} mode")
        return pd.DataFrame.from_records(
            [x.to_pandas_tuple() for x in results],
            columns=[
                "dgst",
                "canonical_reference_keyword",
                "actual_reference_keywords",
                "source",
                "segments",
            ],
        )

    @staticmethod
    def _get_split_dict() -> dict[str, str]:
        """
        Returns dictionary that maps dgst: split, where split in `train`, `valid`, `test`
        """

        def get_single_dct(pth: Path, split_name: str) -> dict[str, str]:
            with pth.open("r") as handle:
                return dict.fromkeys(json.load(handle), split_name)

        split_directory = Path(str(files("sec_certs.data") / "reference_annotations/split/"))
        return {
            **get_single_dct(split_directory / "train.json", "train"),
            **get_single_dct(split_directory / "valid.json", "valid"),
            **get_single_dct(split_directory / "test.json", "test"),
        }

    @staticmethod
    def _get_annotations_dict() -> dict[tuple[str, str], str]:
        """
        Returns dictionary mapping tuples `(dgst, canonical_reference_keyword) -> label`
        """

        def load_single_df(pth: Path, split_name: str) -> pd.DataFrame:
            return (
                pd.read_csv(
                    pth,
                    na_values=["None"],
                    dtype={
                        "dgst": str,
                        "canonical_reference_keyword": str,
                        "source": str,
                        "label": str,
                        "comment": str,
                    },
                )
                .dropna(subset="label")
                .assign(
                    label=lambda df_: df_.label.str.replace(" ", "_").str.upper(),
                    split=split_name,
                )
            )

        annotations_directory = Path(str(files("sec_certs.data") / "reference_annotations/final/"))
        df_annot = pd.concat(
            [
                load_single_df(annotations_directory / "train.csv", "train"),
                load_single_df(annotations_directory / "valid.csv", "valid"),
                load_single_df(annotations_directory / "test.csv", "test"),
            ]
        )

        return (
            df_annot[["dgst", "canonical_reference_keyword", "label"]]
            .set_index(["dgst", "canonical_reference_keyword"])
            .label.to_dict()
        )

    @staticmethod
    def _process_df(df: pd.DataFrame, certs: Iterable[CCCertificate]) -> pd.DataFrame:
        def process_segment(segment: str, actual_reference_keywords: frozenset[str]) -> str:
            segment = " ".join(segment.split())
            for ref_id in actual_reference_keywords:
                segment = segment.replace(ref_id, "REFERENCED_CERTIFICATE_ID")
            return segment

        def unique_elements(series):
            combined = [item for sublist in series for item in sublist]
            return list(set(combined))

        """
        Fully processes the dataframe.
        """
        annotations_dict = ReferenceSegmentExtractor._get_annotations_dict()
        split_dct = ReferenceSegmentExtractor._get_split_dict()
        logger.info(f"Deleting {df.loc[df.segments.isnull()].shape[0]} rows with no segments.")

        df_new = df.copy()
        df_new["full_key"] = df_new.apply(lambda x: (x["dgst"], x["canonical_reference_keyword"]), axis=1)
        to_delete = len(df_new.loc[df_new.segments.isnull()].full_key.unique())
        print(
            f"Deleting records for {to_delete} unique (dgst, referenced_id) pairs, not necessarily labeled ones. These have empty segments."
        )

        df_processed = (
            df.loc[df.segments.notnull()]
            .explode("segments")
            # .assign(lang=lambda df_: df_.segments.map(langdetect.detect))
            # .loc[lambda df_: df_.lang.isin({"en", "fr", "de"})]  # This could get disabled possibly.
            .groupby(
                ["dgst", "canonical_reference_keyword"],
                as_index=False,
                dropna=False,
            )
            .agg({"segments": list, "actual_reference_keywords": unique_elements})
            .assign(
                actual_reference_keywords=lambda df_: df_.actual_reference_keywords.map(list),
                label=lambda df_: [
                    annotations_dict.get(x) for x in zip(df_["dgst"], df_["canonical_reference_keyword"])
                ],
                split=lambda df_: df_.dgst.map(split_dct),
            )
            .assign(
                label=lambda df_: df_.label.map(lambda x: x if x is not None else np.nan),
                split=lambda df_: df_.split.map(lambda x: "test" if pd.isnull(x) else x),
            )
        )
        df_processed.segments = df_processed.apply(
            lambda row: [process_segment(x, row.actual_reference_keywords) for x in row.segments],
            axis=1,
        )
        return df_processed
