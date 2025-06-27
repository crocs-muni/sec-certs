from __future__ import annotations

import itertools
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pandas as pd
import requests
from bs4 import BeautifulSoup

from sec_certs import constants
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.fips_algorithm import FIPSAlgorithm
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers

logger = logging.getLogger(__name__)


class FIPSAlgorithmDataset(JSONPathDataset, ComplexSerializableType):
    def __init__(self, algs: dict[str, FIPSAlgorithm] | None = None, json_path: str | Path | None = None):
        super().__init__(json_path)
        self.algs = algs if algs is not None else {}
        self.alg_number_to_algs: dict[str, set[FIPSAlgorithm]] = {}

        self._build_lookup_dicts()

    @property
    def serialized_attributes(self) -> list[str]:
        return ["algs"]

    def __iter__(self) -> Iterator[FIPSAlgorithm]:
        yield from self.algs.values()

    def __getitem__(self, item: str) -> FIPSAlgorithm:
        return self.algs.__getitem__(item)

    def __setitem__(self, key: str, value: FIPSAlgorithm) -> None:
        self.algs.__setitem__(key, value)

    def __len__(self) -> int:
        return len(self.algs)

    def __contains__(self, item: FIPSAlgorithm) -> bool:
        if not isinstance(item, FIPSAlgorithm):
            raise ValueError(f"{item} is not of FIPSAlgorithm class")
        return item.dgst in self.algs and self.algs[item.dgst] == item

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FIPSAlgorithmDataset) and self.algs == other.algs

    @classmethod
    def from_web(cls, json_path: str | Path | None = None) -> FIPSAlgorithmDataset:
        with TemporaryDirectory() as tmp_dir:
            htmls = FIPSAlgorithmDataset.download_alg_list_htmls(Path(tmp_dir))
            algs = set(itertools.chain.from_iterable(FIPSAlgorithmDataset.parse_algorithms_from_html(x) for x in htmls))
        return cls({x.dgst: x for x in algs}, json_path=json_path)

    @staticmethod
    def download_alg_list_htmls(output_dir: Path) -> list[Path]:
        first_page_path = output_dir / "page1.html"
        ITEMS_PER_PAGE = "ipp=250"

        res = helpers.download_file(constants.FIPS_ALG_SEARCH_URL + "1&" + ITEMS_PER_PAGE, first_page_path)
        if res != requests.codes.ok:
            res = helpers.download_file(constants.FIPS_ALG_SEARCH_URL + "1&" + ITEMS_PER_PAGE, first_page_path)
            if res != requests.codes.ok:
                logger.error(f"Could not build Algorithm dataset, got server response: {res}")
                raise ValueError(f"Could not build Algorithm dataset, got server response: {res}")

        n_pages = FIPSAlgorithmDataset.get_number_of_html_pages(first_page_path)

        urls = [constants.FIPS_ALG_SEARCH_URL + str(i) + "&" + ITEMS_PER_PAGE for i in range(2, n_pages + 1)]
        paths = [output_dir / f"page{i}.html" for i in range(2, n_pages + 1)]
        responses = helpers.download_parallel(urls, paths, progress_bar_desc="Downloading FIPS Algorithm HTMLs")

        failed_tuples = [(url, path) for url, path, resp in zip(urls, paths, responses) if resp != requests.codes.ok]
        if failed_tuples:
            failed_urls, failed_paths = zip(*failed_tuples)
            responses = helpers.download_parallel(failed_urls, failed_paths)
            if any(x != requests.codes.ok for x in responses):
                raise ValueError("Failed to download the algorithms HTML data, the dataset won't be constructed.")

        return paths

    @staticmethod
    def download_algs_data(output_dir: Path, alg_links: list[str]) -> list[Path]:
        urls = [constants.FIPS_CAVP_URL + "/" + i for i in alg_links]
        paths = [output_dir / f"alg_page{i}.html" for i in range(0, len(alg_links))]
        responses = helpers.download_parallel(urls, paths, progress_bar_desc="Downloading FIPS Algorithm data")

        failed_tuples = [
            (url, path) for url, path, resp in zip(urls, paths, responses) if resp != constants.RESPONSE_OK
        ]
        if failed_tuples:
            failed_urls, failed_paths = zip(*failed_tuples)
            responses = helpers.download_parallel(failed_urls, failed_paths)
            if any(x != constants.RESPONSE_OK for x in responses):
                raise ValueError("Failed to download the algorithms data, the dataset won't be constructed.")

        return paths

    @staticmethod
    def get_number_of_html_pages(html_path: Path) -> int:
        with html_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")
        return int(soup.select("span[data-total-pages]")[0].attrs["data-total-pages"])

    @staticmethod
    def parse_alg_data_from_html(html_path: Path) -> tuple[str, str, str, str]:
        fields = []
        with html_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")
            for field in ["Description", "Version", "Type"]:
                div = soup.find("div", text=field)
                fields.append("" if div is None else div.find_next_sibling("div").get_text())
            capability_trs = soup.find("table").find("tbody").findAll("tr")
            capabilities = [c.findAll("td")[1].find(["b", "s"]).get_text().strip() for c in capability_trs]
        return fields[0], fields[1], fields[2], ", ".join(capabilities)

    @staticmethod
    def parse_algorithms_from_html(html_path: Path) -> set[FIPSAlgorithm]:
        df = pd.read_html(html_path, extract_links="body")[0]
        for col in df.columns:
            if "Order by" in col:
                df.rename(columns={col: col.split("Order by")[0]}, inplace=True)
        df = df.assign(
            alg_type=df["Validation Number"].map(lambda x: re.sub(r"[0-9\s]", "", x[0])),
            alg_number=df["Validation Number"].map(lambda x: re.sub(r"[^0-9]", "", x[0])),
            Vendor=df["Vendor"].map(lambda x: x[0]),
            Implementation=df["Implementation"].map(lambda x: x[0]),
            Validation_Date=df["Validation Date"].map(lambda x: x[0])
        )
        links = [x[1] for x in df["Validation Number"]]

        with TemporaryDirectory() as tmp_dir:
            alg_pages = FIPSAlgorithmDataset.download_algs_data(Path(tmp_dir), links)
            parsed_data = [FIPSAlgorithmDataset.parse_alg_data_from_html(page) for page in alg_pages]
            descriptions, versions, types, capabilities = zip(*parsed_data)
        df = df.assign(description=descriptions, version=versions, type=types, algorithm_capabilities=capabilities)

        return set(
            df.apply(
                lambda row: FIPSAlgorithm(
                    row["alg_number"],
                    row["alg_type"],
                    row["Vendor"],
                    row["Implementation"],
                    row["Validation Date"],
                    row["description"],
                    row["version"],
                    row["type"],
                    row["algorithm_capabilities"],
                ),
                axis=1,
            )
        )

    def to_pandas(self) -> pd.DataFrame:
        return pd.DataFrame([x.pandas_tuple for x in self], columns=FIPSAlgorithm.pandas_columns).set_index("dgst")

    def _build_lookup_dicts(self) -> None:
        for alg in self:
            if alg.alg_number not in self.alg_number_to_algs:
                self.alg_number_to_algs[alg.alg_number] = {alg}
            else:
                self.alg_number_to_algs[alg.alg_number].add(alg)

    def get_algorithms_by_id(self, alg_number: str) -> set[FIPSAlgorithm]:
        return self.alg_number_to_algs.get(alg_number, set())
