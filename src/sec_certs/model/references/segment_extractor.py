from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import langdetect
import pandas as pd
import spacy
from importlib_resources import files

from sec_certs.sample.cc import CCCertificate
from sec_certs.utils import parallel_processing

nlp = spacy.load("en_core_web_sm")


@dataclass
class ReferenceRecord:
    """
    Data structure to hold objects when extracting text segments from txt files relevant for reference annotations.
    """

    certificate: CCCertificate
    referenced_cert_id: str
    source: str
    segments: set[str] | None = None

    @staticmethod
    def fill_reference_segments(record: ReferenceRecord) -> ReferenceRecord:
        """
        Open file, read text and extract sentences with `referenced_cert_id` match.
        Static method to allow for parallelization
        """
        pth_to_read = (
            record.certificate.state.st_txt_path
            if record.source == "target"
            else record.certificate.state.report_txt_path
        )

        with pth_to_read.open("r") as handle:
            data = handle.read()

        record.segments = {sent.text for sent in nlp(data).sents if record.referenced_cert_id in sent.text}
        if not record.segments:
            record.segments = None
        return record

    def to_pandas_tuple(self) -> tuple[str, str, str, set[str] | None]:
        return self.certificate.dgst, self.referenced_cert_id, self.source, self.segments


class ReferenceSegmentExtractor:
    """
    Class to process list of certificates into a dataframe that holds reference segments. Exploses single method
    Should be only called with ReferenceSegmentExtractor().prepare_df_from_cc_certs(list_of_certificates)
    """

    def __init__(self):
        pass

    def prepare_df_from_cc_certs(self, certs: list[CCCertificate]) -> pd.DataFrame:
        """
        Prepares processed DataFrame for reference annotator training from a list of certificates. This method:
        - Extracts text segments relevant for each reference out of the certificates, forms dataframe from those
        - Loads data splits into train/valid/test
        - Loads manually annotated samples
        - Combines all of that into single dataframe
        """
        df_targets = self._build_df(
            [x for x in certs if x.heuristics.st_references.directly_referencing and x.state.st_txt_path], "target"
        )
        df_reports = self._build_df(
            [x for x in certs if x.heuristics.report_references.directly_referencing and x.state.report_txt_path],
            "report",
        )
        df = pd.concat([df_targets, df_reports])
        return self._process_df(df)

    def _build_df(self, certs: list[CCCertificate], source: Literal["target", "report"]) -> pd.DataFrame:
        """ """
        attribute_mapping = {"target": "st_references", "report": "report_references"}
        records = [
            ReferenceRecord(x, y, source)
            for x in certs
            for y in getattr(x.heuristics, attribute_mapping[source]).directly_referencing
        ]

        # results = [ReferenceRecord.fill_reference_segments(x) for x in tqdm.tqdm(records)]
        results = parallel_processing.process_parallel(
            ReferenceRecord.fill_reference_segments,
            records,
            use_threading=False,
            progress_bar=True,
            progress_bar_desc=f"Recovering reference segments for {source}s",
        )

        return pd.DataFrame.from_records(
            [x.to_pandas_tuple() for x in results],
            columns=["dgst", "referenced_cert_id", "source", "segments"],
        )

    def _get_split_dict(self) -> dict[str, str]:
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

    def _get_annotations_dict(self) -> dict[tuple[str, str], str]:
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
        )[["dgst", "referenced_cert_id", "source", "label", "comment"]]

        return (
            df_annot[["dgst", "referenced_cert_id", "label"]].set_index(["dgst", "referenced_cert_id"]).label.to_dict()
        )

    def _process_df(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Fully processes the dataframe.
        """
        annotations_dict = self._get_annotations_dict()
        split_dct = self._get_split_dict()

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
