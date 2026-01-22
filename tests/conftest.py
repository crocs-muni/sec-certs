import json
from collections.abc import Generator
from importlib.resources import as_file, files
from pathlib import Path

import pytest
from rapidfuzz import fuzz

import tests.data.common
from sec_certs.configuration import config
from sec_certs.converter import has_docling, has_pdftotext
from sec_certs.dataset import CPEDataset, CVEDataset
from sec_certs.utils.strings import normalize_whitespace


def get_converters():
    converters = []
    if has_pdftotext:
        from sec_certs.converter import PdftotextConverter

        converters.append(PdftotextConverter)
    if has_docling:
        from sec_certs.converter import DoclingConverter

        converters.append(pytest.param(DoclingConverter, marks=pytest.mark.docling))
    return converters


def compare_to_template(template: Path, actual: Path) -> None:
    with template.open("r", encoding="utf-8") as f:
        template_text = f.read()

    with actual.open("r", encoding="utf-8") as f:
        actual_text = f.read()

    template_text = normalize_whitespace(template_text)
    actual_text = normalize_whitespace(actual_text)
    ratio = fuzz.ratio(template_text, actual_text)
    assert ratio >= 95


@pytest.fixture(scope="module", autouse=True)
def load_test_config():
    with as_file(files(tests.data.common) / "settings_tests.yml") as path:
        config.load_from_yaml(path)


@pytest.fixture(scope="module")
def cve_dataset_path() -> Generator[Path, None, None]:
    with as_file(files(tests.data.common) / "cve_dataset.json") as cve_dataset_path:
        yield cve_dataset_path


@pytest.fixture(scope="module")
def cpe_match_feed() -> dict:
    with as_file(files(tests.data.common) / "cpe_match_feed.json") as path, path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data


@pytest.fixture(scope="module")
def cve_dataset(cve_dataset_path: Path, cpe_match_feed: dict) -> CVEDataset:
    cve_dataset = CVEDataset.from_json(cve_dataset_path)
    cve_dataset.build_lookup_dict(cpe_match_feed)
    return cve_dataset


@pytest.fixture(scope="module")
def cpe_dataset_path() -> Generator[Path, None, None]:
    with as_file(files(tests.data.common) / "cpe_dataset.json") as cpe_dataset_path:
        yield cpe_dataset_path


@pytest.fixture(scope="module")
def cpe_dataset(cpe_dataset_path: Path) -> CPEDataset:
    return CPEDataset.from_json(cpe_dataset_path)
