from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from urllib.parse import parse_qs, urlparse

import pandas as pd
import requests
from bs4 import BeautifulSoup, Tag

from sec_certs import constants
from sec_certs.configuration import config
from sec_certs.sample.fips_algorithm import FIPSAlgorithm
from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils import helpers
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


def _parse_alg_type_and_number(text: str) -> tuple[str, str] | None:
    alg_type = re.sub(r"[0-9\s]", "", text)
    alg_number = re.sub(r"[^0-9]", "", text)
    if not alg_type or not alg_number:
        return None
    return alg_type, alg_number


@dataclass
class ProductPageData:
    description: str | None = None
    version: str | None = None
    product_type: str | None = None
    validations: dict[str, list[tuple[str, str | None]]] = field(default_factory=dict)

    @classmethod
    def from_html(cls, html_path: Path) -> ProductPageData:
        try:
            with html_path.open("r") as handle:
                soup = BeautifulSoup(handle, "html5lib")
        except Exception:
            logger.warning(f"Failed to read product page: {html_path}")
            return cls()

        try:
            return cls(
                description=cls._parse_description(soup),
                version=cls._parse_element_text(soup, "product-version"),
                product_type=cls._parse_element_text(soup, "product-type"),
                validations=cls._parse_validations(soup),
            )
        except Exception:
            logger.warning(f"Failed to parse product page: {html_path}", exc_info=True)
            return cls()

    @staticmethod
    def _parse_element_text(soup: BeautifulSoup, element_id: str) -> str | None:
        el = soup.find(id=element_id)
        return el.get_text(strip=True) or None if el else None

    @staticmethod
    def _parse_description(soup: BeautifulSoup) -> str | None:
        for padrow in soup.find_all("div", class_="padrow"):
            label_div = padrow.find("div", class_="col-md-2")
            if label_div and label_div.get_text(strip=True) == "Description":
                value_div = padrow.find("div", class_="col-md-10")
                return value_div.get_text(strip=True) or None if value_div else None
        return None

    @staticmethod
    def _parse_capability_environment_pairs(form: Tag) -> list[tuple[str, str | None]]:
        pairs: list[tuple[str, str | None]] = []
        for tr in form.select("table tr"):
            tds = tr.find_all("td")
            if len(tds) < 2:
                continue

            oe = re.sub(r"\s*Expand\s*$", "", tds[0].get_text(strip=True)).strip() or None
            if oe == "N/A":
                oe = None

            for cap_link in tds[1].find_all("a", href=re.compile(r"Validation-Notes#")):
                cap_text = cap_link.get_text(strip=True).rstrip(":")
                if cap_text:
                    pairs.append((cap_text, oe))
        return pairs

    @staticmethod
    def _parse_validations(soup: BeautifulSoup) -> dict[str, list[tuple[str, str | None]]]:
        validations: dict[str, list[tuple[str, str | None]]] = {}
        for form in soup.find_all("form", attrs={"method": "get"}):
            val_link = form.select_one("h4 a[href*='details?validation=']")
            if not val_link:
                continue

            parsed = _parse_alg_type_and_number(val_link.get_text(strip=True))
            if not parsed:
                continue

            dgst = f"{parsed[0]} {parsed[1]}"
            pairs = ProductPageData._parse_capability_environment_pairs(form)
            validations[dgst] = sorted(pairs, key=lambda x: (x[0], x[1] or ""))
        return validations


class FIPSAlgorithmDataset(ComplexSerializableType):
    JSON_FILENAME = "algorithms_dataset.json"

    def __init__(self, algs: dict[str, FIPSAlgorithm] | None = None, root_dir: str | Path | None = None):
        self.algs = algs if algs is not None else {}
        self.root_dir = Path(root_dir) if root_dir is not None else None

    @property
    def serialized_attributes(self) -> list[str]:
        return ["algs"]

    @property
    def is_backed(self) -> bool:
        return self.root_dir is not None

    @property
    def json_path(self) -> Path | None:
        if self.root_dir is None:
            return None
        return self.root_dir / self.JSON_FILENAME

    @property
    def html_dir(self) -> Path | None:
        if self.root_dir is None:
            return None
        return self.root_dir / "html"

    def __iter__(self) -> Iterator[FIPSAlgorithm]:
        yield from self.algs.values()

    def __getitem__(self, item: str) -> FIPSAlgorithm:
        return self.algs[item]

    def __setitem__(self, key: str, value: FIPSAlgorithm) -> None:
        self.algs[key] = value

    def __len__(self) -> int:
        return len(self.algs)

    def __contains__(self, item: FIPSAlgorithm) -> bool:
        if not isinstance(item, FIPSAlgorithm):
            raise ValueError(f"{item} is not of FIPSAlgorithm class")
        return item.dgst in self.algs and self.algs[item.dgst] == item

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FIPSAlgorithmDataset) and self.algs == other.algs

    @classmethod
    def from_web(cls, root_dir: str | Path | None = None) -> FIPSAlgorithmDataset:
        dset = cls(root_dir=root_dir)
        html_dir = dset.html_dir
        ctx = TemporaryDirectory() if html_dir is None else nullcontext(Path(html_dir))

        with ctx as working_dir_raw:
            working_dir = Path(working_dir_raw)
            list_html_dir = working_dir / "alg_list"
            list_html_dir.mkdir(parents=True, exist_ok=True)

            htmls = cls.download_alg_list_htmls(list_html_dir)

            all_algs: set[FIPSAlgorithm] = set()
            dgst_to_product_id: dict[str, str] = {}
            for html in tqdm(htmls, desc="Parsing algorithm list pages"):
                algs, dgst_to_pid = cls.parse_algorithms_from_html(html)
                all_algs.update(algs)
                dgst_to_product_id.update(dgst_to_pid)

            unique_pids = set(dgst_to_product_id.values())
            products_dir = working_dir / "products"
            products_dir.mkdir(parents=True, exist_ok=True)
            pid_to_path = cls.download_product_htmls(unique_pids, products_dir)

            pid_to_data: dict[str, ProductPageData] = {}
            for pid, path in tqdm(pid_to_path.items(), desc="Parsing product pages"):
                pid_to_data[pid] = ProductPageData.from_html(path)

            dset.algs = cls._enrich_with_product_data(all_algs, dgst_to_product_id, pid_to_data)

        if dset.is_backed:
            dset.to_json()
        return dset

    @staticmethod
    def _enrich_with_product_data(
        algs: set[FIPSAlgorithm],
        dgst_to_product_id: dict[str, str],
        pid_to_data: dict[str, ProductPageData],
    ) -> dict[str, FIPSAlgorithm]:
        enriched: dict[str, FIPSAlgorithm] = {}
        for alg in algs:
            alg_pid = dgst_to_product_id.get(alg.dgst)
            product_data = pid_to_data.get(alg_pid) if alg_pid else None

            if product_data is None:
                enriched[alg.dgst] = alg
                continue

            pairs = product_data.validations.get(alg.dgst)

            new_alg = replace(
                alg,
                product_id=alg_pid,
                description=product_data.description,
                version=product_data.version,
                product_type=product_data.product_type,
                capability_environment_pairs=tuple(pairs) if pairs else None,
            )
            enriched[new_alg.dgst] = new_alg

        return enriched

    @staticmethod
    def _download_parallel_with_retries(urls: list[str], paths: list[Path], progress_bar_desc: str = "") -> list[str]:
        failed_urls = list(urls)
        failed_paths = list(paths)
        for attempt in range(1, config.n_download_attempts + 1):
            responses = helpers.download_parallel(
                failed_urls, failed_paths, progress_bar_desc=f"{progress_bar_desc} (Attempt {attempt})"
            )
            failed = [
                (url, path)
                for url, path, resp in zip(failed_urls, failed_paths, responses)
                if resp != requests.codes.ok
            ]
            if not failed:
                return []
            failed_urls = [t[0] for t in failed]
            failed_paths = [t[1] for t in failed]
            logger.info(f"Attempt {attempt}/{config.n_download_attempts}: {len(failed)} downloads failed, retrying.")
        return failed_urls

    @staticmethod
    def download_alg_list_htmls(output_dir: Path) -> list[Path]:
        first_page_path = output_dir / "page1.html"
        items_per_page = "ipp=250"

        first_page_url = constants.FIPS_ALG_SEARCH_URL + "1&" + items_per_page
        for _ in range(config.n_download_attempts):
            res = helpers.download_file(first_page_url, first_page_path)
            if res == requests.codes.ok:
                break
        else:
            logger.error(f"Could not build Algorithm dataset, got server response: {res}")
            raise ValueError(f"Could not build Algorithm dataset, got server response: {res}")

        n_pages = FIPSAlgorithmDataset.get_number_of_html_pages(first_page_path)

        urls = [constants.FIPS_ALG_SEARCH_URL + str(i) + "&" + items_per_page for i in range(2, n_pages + 1)]
        paths = [output_dir / f"page{i}.html" for i in range(2, n_pages + 1)]

        failed = FIPSAlgorithmDataset._download_parallel_with_retries(
            urls, paths, progress_bar_desc="Downloading FIPS Algorithm HTMLs"
        )
        if failed:
            raise ValueError("Failed to download the algorithms HTML data, the dataset won't be constructed.")

        return [first_page_path] + paths

    @staticmethod
    def get_number_of_html_pages(html_path: Path) -> int:
        with html_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")
        return int(soup.select("span[data-total-pages]")[0].attrs["data-total-pages"])

    @staticmethod
    def _extract_product_info(impl_cell: Tag) -> tuple[str, str | None]:
        product_link = impl_cell.find("a", id=re.compile(r"^product-name-"))
        if not product_link or not isinstance(product_link, Tag):
            return impl_cell.get_text(strip=True), None

        impl_name = product_link.get_text(strip=True)
        href = product_link.get("href", "")
        if isinstance(href, str):
            product_vals = parse_qs(urlparse(href).query).get("product", [])
            return impl_name, product_vals[0] if product_vals else None
        return impl_name, None

    @staticmethod
    def _parse_validation_link(cell: Tag) -> tuple[str, str] | None:
        validation_link = cell.find("a", id=re.compile(r"^validation-number-"))
        if not validation_link or not isinstance(validation_link, Tag):
            return None
        return _parse_alg_type_and_number(validation_link.get_text(strip=True))

    @staticmethod
    def parse_algorithms_from_html(html_path: Path) -> tuple[set[FIPSAlgorithm], dict[str, str]]:
        with html_path.open("r") as handle:
            soup = BeautifulSoup(handle, "html5lib")

        table = soup.find("table")
        if not table or not isinstance(table, Tag):
            return set(), {}

        tbody = table.find("tbody")
        if not tbody or not isinstance(tbody, Tag):
            return set(), {}

        algs: set[FIPSAlgorithm] = set()
        dgst_to_pid: dict[str, str] = {}

        current_vendor: str | None = None
        current_impl: str | None = None
        current_pid: str | None = None

        for row in tbody.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue

            if len(cells) >= 4:
                current_vendor = cells[0].get_text(strip=True)
                current_impl, current_pid = FIPSAlgorithmDataset._extract_product_info(cells[1])
                validation_cell, date_cell = cells[2], cells[3]
            elif len(cells) >= 2:
                validation_cell, date_cell = cells[0], cells[1]
            else:
                continue

            parsed = FIPSAlgorithmDataset._parse_validation_link(validation_cell)
            if not parsed:
                continue
            alg_type, alg_number = parsed

            validation_date = datetime.strptime(date_cell.get_text(strip=True), "%m/%d/%Y").date()

            alg = FIPSAlgorithm(
                alg_number=alg_number,
                algorithm_type=alg_type,
                vendor=current_vendor or "",
                implementation_name=current_impl or "",
                validation_date=validation_date,
            )
            algs.add(alg)
            if current_pid:
                dgst_to_pid[alg.dgst] = current_pid

        return algs, dgst_to_pid

    @staticmethod
    def download_product_htmls(product_ids: set[str], output_dir: Path) -> dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)

        to_download_ids = []
        existing: dict[str, Path] = {}
        for pid in product_ids:
            path = output_dir / f"product_{pid}.html"
            if path.exists():
                existing[pid] = path
            else:
                to_download_ids.append(pid)

        if not to_download_ids:
            return existing

        urls = [constants.FIPS_CAVP_URL + f"/details?product={pid}" for pid in to_download_ids]
        paths = [output_dir / f"product_{pid}.html" for pid in to_download_ids]

        failed = FIPSAlgorithmDataset._download_parallel_with_retries(
            urls, paths, progress_bar_desc="Downloading FIPS product pages"
        )
        if failed:
            logger.warning(
                f"Failed to download {len(failed)} product pages after {config.n_download_attempts} attempts. "
                f"The dataset will be incomplete."
            )

        result = dict(existing)
        for pid, path in zip(to_download_ids, paths):
            if path.exists():
                result[pid] = path

        return result

    @classmethod
    def from_json(cls, input_path: str | Path, is_compressed: bool = False) -> FIPSAlgorithmDataset:
        dset = cast("FIPSAlgorithmDataset", ComplexSerializableType.from_json(input_path, is_compressed))
        dset.root_dir = Path(input_path).parent.absolute()
        return dset

    def to_pandas(self) -> pd.DataFrame:
        return pd.DataFrame([x.pandas_tuple for x in self], columns=FIPSAlgorithm.pandas_columns).set_index("dgst")
