from __future__ import annotations

import json
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


def fill_reference_segments_spacy(record: ReferenceRecord) -> ReferenceRecord:
    """
    Open file, read text and extract sentences with `referenced_cert_id` match.
    """
    with record.data_source_path.open("r") as handle:
        data = handle.read()

    record.segments = {sent.text for sent in nlp(data).sents if record.referenced_cert_id in sent.text}

    if not record.segments:
        record.segments = None

    return record


def fill_reference_segments_ocr(record: ReferenceRecord) -> ReferenceRecord:
    """
    Fill the segment data from jsons produced by OCR and segmentation.
    """
    with record.data_source_path.open("r") as handle:
        data = json.load(handle)

    record.segments = set()
    # TODO: Now we're taking the first segment encountered. This is not ideal, but we don't have a better solution yet.
    for segment in data:
        first_segment = segment["low_level_segments"][0]
        if (
            ((first_segment["type"] == "Text") or (first_segment["type"] == "Title"))
            and "text" in first_segment
            and record.referenced_cert_id in first_segment["text"]
        ):
            record.segments.add(first_segment["text"])

    if not record.segments:
        record.segments = None

    return record


@dataclass
class ReferenceRecord:
    """
    Data structure to hold objects when extracting text segments from txt files relevant for reference annotations.
    """

    certificate_dgst: str
    data_source_path: Path
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

    def __init__(self, segmenter: Literal["spacy", "ocr"] = "spacy", ocr_json_dir: Path | None = None):
        self.segmenter = segmenter
        self.ocr_json_dir = ocr_json_dir

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
        return ReferenceSegmentExtractor._process_df(pd.concat([df_targets, df_reports]))

    def _build_records(
        self, certs: Iterable[CCCertificate], source: Literal["target", "report"]
    ) -> list[ReferenceRecord]:
        if self.segmenter == "spacy":
            return self._build_records_spacy(certs, source)
        else:
            return self._build_records_ocr(certs, source)

    def _build_records_spacy(
        self, certs: Iterable[CCCertificate], source: Literal["target", "report"]
    ) -> list[ReferenceRecord]:
        attribute_mapping = {"target": "st_references", "report": "report_references"}
        file_to_read = "st_txt_path" if source == "target" else "report_txt_path"
        return [
            ReferenceRecord(x.dgst, getattr(x.state, file_to_read), y, source)
            for x in certs
            for y in getattr(x.heuristics, attribute_mapping[source]).directly_referencing
        ]

    def _build_records_ocr(
        self, certs: Iterable[CCCertificate], source: Literal["target", "report"]
    ) -> list[ReferenceRecord]:
        attribute_mapping = {"target": "st_references", "report": "report_references"}
        dir_to_read = "reports" if source == "report" else "targets"
        if not self.ocr_json_dir:
            raise ValueError("OCR json directory must be specified when using OCR segmenter")
        return [
            ReferenceRecord(x.dgst, self.ocr_json_dir / dir_to_read / f"{x.dgst}.json", y, source)
            for x in certs
            for y in getattr(x.heuristics, attribute_mapping[source]).directly_referencing
        ]

    def _build_df(self, certs: Iterable[CCCertificate], source: Literal["target", "report"]) -> pd.DataFrame:
        records = self._build_records(certs, source)
        func = fill_reference_segments_spacy if self.segmenter == "spacy" else fill_reference_segments_ocr
        results = parallel_processing.process_parallel(
            func,
            records,
            use_threading=False,
            progress_bar=True,
            progress_bar_desc=f"Recovering reference segments for {source}s",
        )
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
