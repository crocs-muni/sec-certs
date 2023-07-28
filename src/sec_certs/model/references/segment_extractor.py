from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

import langdetect
import pandas as pd
import spacy
from importlib_resources import files

from sec_certs.sample.cc import CCCertificate
from sec_certs.utils import parallel_processing

nlp = spacy.load("en_core_web_sm")


def references_to_label_studio(df: pd.DataFrame, filepath: Path) -> None:
    """
    Prepares a DataFrame obtained from ReferenceSegmentExtractor to be used in Label Studio for manual annotation.
    It then suffices to use "Natural Language Processing" -> "Text Classification" task in Label Studio.
    """

    def split(segments: list[str]) -> str:
        res = ""
        for x in segments:
            res += "* Segment: " + x + "\n\n"
        return res

    df["text"] = df["segments"].apply(split)
    df.loc[:, ["dgst", "referenced_cert_id", "text"]].to_json(filepath, indent=4, orient="records")


def fill_reference_segments(record: ReferenceRecord) -> ReferenceRecord:
    """
    Open file, read text and extract sentences with `referenced_cert_id` match.
    """
    with record.processed_data_source_path.open("r") as handle:
        data = handle.read()

    sentences_with_hits = [sent.text for sent in nlp(data).sents if record.referenced_cert_id in sent.text]
    if not sentences_with_hits:
        record.segments = None
        return record

    record.segments = set()
    for index, sent in enumerate(sentences_with_hits):
        to_add = ""
        if index > 0:
            to_add += sentences_with_hits[index - 1]

        to_add += sent

        if index < len(sentences_with_hits) - 1:
            to_add += sentences_with_hits[index + 1]

        record.segments.add(to_add)

    # record.segments = {sent.text for sent in nlp(data).sents if record.referenced_cert_id in sent.text}

    # if not record.segments:
    #     record.segments = None

    return record


def preprocess_data_source(record: ReferenceRecord) -> ReferenceRecord:
    # TODO: This shall be reactivate only when we delete the processed data source files after finnishing
    # if record.processed_data_source_path.exists():
    #     return record

    with record.raw_data_source_path.open("r") as handle:
        data = handle.read()

    processed_data = preprocess_txt_func(data, record.referenced_cert_id)

    with record.processed_data_source_path.open("w") as handle:
        handle.write(processed_data)

    return record


def find_bracket_pattern(sentences, exact_match):
    pattern = r"(\[.+?\])(?=.*" + exact_match + r")"
    res = []
    for sent in sentences:
        matches = re.findall(pattern, sent, flags=re.MULTILINE | re.UNICODE | re.DOTALL)
        if matches:
            res.append(matches[-1])
    return res


def preprocess_txt_func(data: str, referenced_cert_id: str) -> str:
    data = replace_acronyms(data)
    data = replace_citation_identifiers(data, referenced_cert_id)
    return data


def replace_citation_identifiers(data: str, referenced_cert_id: str) -> str:
    segments = {sent.text for sent in nlp(data).sents if referenced_cert_id in sent.text}
    patterns_to_replace = find_bracket_pattern(segments, referenced_cert_id)
    for pattern in patterns_to_replace:
        data = data.replace(pattern, referenced_cert_id)
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
    referenced_cert_id: str
    source: str
    segments: set[str] | None = None

    def to_pandas_tuple(self) -> tuple[str, str, str, set[str] | None]:
        return self.certificate_dgst, self.referenced_cert_id, self.source, self.segments


class ReferenceSegmentExtractor:
    """
    Class to process list of certificates into a dataframe that holds reference segments.
    Should be only called with ReferenceSegmentExtractor()(list_of_certificates)
    """

    def __init__(self):
        pass

    def __call__(self, certs: Iterable[CCCertificate]) -> pd.DataFrame:
        return self._prepare_df_from_cc_certs(certs)

    def _prepare_df_from_cc_certs(self, certs: Iterable[CCCertificate]) -> pd.DataFrame:
        """
        Prepares processed DataFrame for reference annotator training from a list of certificates. This method:
        - Extracts text segments relevant for each reference out of the certificates, forms dataframe from those
        - Loads data splits into train/valid/test
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
        return ReferenceSegmentExtractor._process_df(pd.concat([df_targets, df_reports]))

    def _build_records(self, certs: list[CCCertificate], source: Literal["target", "report"]) -> list[ReferenceRecord]:
        def get_cert_records(cert: CCCertificate, source: Literal["target", "report"]) -> list[ReferenceRecord]:
            ref_var = {"target": "st_references", "report": "report_references"}
            raw_source_var = {"target": "st_txt_path", "report": "report_txt_path"}

            references = getattr(cert.heuristics, ref_var[source]).directly_referencing
            raw_source_dir = getattr(cert.state, raw_source_var[source]).parent
            processed_source_dir = raw_source_dir.parent / "txt_processed"

            return [
                ReferenceRecord(
                    cert.dgst, raw_source_dir / f"{cert.dgst}.txt", processed_source_dir / f"{cert.dgst}.txt", x, source
                )
                for x in references
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

        results = parallel_processing.process_parallel(
            fill_reference_segments,
            records,
            use_threading=False,
            progress_bar=True,
            progress_bar_desc="Recovering reference segments",
        )
        print(f"I now have {len(results)} in {source} mode")
        return pd.DataFrame.from_records(
            [x.to_pandas_tuple() for x in results],
            columns=["dgst", "referenced_cert_id", "source", "segments"],
        )

    @staticmethod
    def _get_split_dict() -> dict[str, str]:
        """
        Returns dictionary that maps dgst: split, where split in `train`, `valid`, `test`
        """

        def get_single_dct(pth: Path, split_name: str) -> dict[str, str]:
            with pth.open("r") as handle:
                return dict.fromkeys(json.load(handle), split_name)

        split_directory = files("sec_certs.data") / "reference_annotations/split/"
        return {
            **get_single_dct(split_directory / "train.json", "train"),
            **get_single_dct(split_directory / "valid.json", "valid"),
            **get_single_dct(split_directory / "test.json", "test"),
        }

    @staticmethod
    def _get_annotations_dict() -> dict[tuple[str, str], str]:
        """
        Returns dictionary mapping tuples `(dgst, referenced_cert_id) -> label`
        """

        def load_single_df(pth: Path, split_name: str) -> pd.DataFrame:
            return (
                pd.read_csv(pth)
                .assign(label=lambda df_: df_.label.str.replace(" ", "_").str.upper(), split=split_name)
                .replace("NONE", None)
                .dropna(subset="label")
            )

        annotations_directory = files("sec_certs.data") / "reference_annotations/manual_annotations/"
        df_annot = pd.concat(
            [
                load_single_df(annotations_directory / "train.csv", "train"),
                load_single_df(annotations_directory / "valid.csv", "valid"),
                load_single_df(annotations_directory / "test.csv", "test"),
            ]
        )

        return (
            df_annot[["dgst", "referenced_cert_id", "label"]].set_index(["dgst", "referenced_cert_id"]).label.to_dict()
        )

    @staticmethod
    def _process_df(df: pd.DataFrame) -> pd.DataFrame:
        """
        Fully processes the dataframe.
        """
        annotations_dict = ReferenceSegmentExtractor._get_annotations_dict()
        split_dct = ReferenceSegmentExtractor._get_split_dict()

        return (
            df.loc[df.segments.notnull()]
            .explode("segments")
            .assign(lang=lambda df_: df_.segments.map(langdetect.detect))
            .loc[lambda df_: df_.lang.isin({"en", "fr", "de"})]
            .groupby(["dgst", "referenced_cert_id", "source"], as_index=False, dropna=False)
            .agg({"segments": list, "lang": list})
            .assign(
                split=lambda df_: df_.dgst.map(split_dct),
                label=lambda df_: [annotations_dict.get(x) for x in zip(df_["dgst"], df_["referenced_cert_id"])],
            )
            .loc[lambda df_: df_["split"] != "test"]
            .groupby(["dgst", "referenced_cert_id", "label", "split"], as_index=False, dropna=False)
            .agg({"segments": sum, "lang": sum})
        )
