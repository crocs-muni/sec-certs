from __future__ import annotations

from datetime import date
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import tests.data.fips.dataset

from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset, ProductPageData, _parse_alg_type_and_number
from sec_certs.sample.fips_algorithm import FIPSAlgorithm
from sec_certs.serialization.json import SerializationError


@pytest.fixture(scope="module")
def alg_dset() -> FIPSAlgorithmDataset:
    with as_file(files(tests.data.fips.dataset) / "alg_dataset.json") as alg_dset_path:
        return FIPSAlgorithmDataset.from_json(alg_dset_path)


@pytest.fixture(scope="module")
def alg_dict() -> dict[str, Any]:
    return {
        "alg_number": "123",
        "algorithm_type": "AES",
        "vendor": "Test Vendor",
        "implementation_name": "Test Impl",
        "validation_date": "2024-01-01",
        "product_id": "999",
        "description": "A test description",
        "version": "2.0",
        "product_type": "SOFTWARE",
        "capability_environment_pairs": [["AES-CBC", "Linux x86_64"], ["AES-GCM", "Linux x86_64"]],
    }


@pytest.fixture(scope="module")
def alg(alg_dict: dict[str, Any]) -> FIPSAlgorithm:
    return FIPSAlgorithm.from_dict(alg_dict)


@pytest.fixture(scope="module")
def alg_list_html_path() -> Path:
    with as_file(files(tests.data.fips.dataset) / "alg_list_page.html") as p:
        return Path(p)


@pytest.fixture(scope="module")
def product_page_html_path() -> Path:
    with as_file(files(tests.data.fips.dataset) / "product_page.html") as p:
        return Path(p)


def test_alg_from_to_dict(alg: FIPSAlgorithm):
    ret = alg.to_dict()
    other = FIPSAlgorithm.from_dict(ret)
    assert alg == other


def test_fips_algorithm_page_url_unchanged(alg: FIPSAlgorithm):
    assert "source=AES" in alg.page_url
    assert "number=123" in alg.page_url


def test_parse_algorithms_from_html(alg_list_html_path: Path):
    algs, dgst_to_pid = FIPSAlgorithmDataset.parse_algorithms_from_html(alg_list_html_path)

    assert len(algs) == 3
    assert len(dgst_to_pid) == 3

    for alg in algs:
        assert alg.alg_number
        assert alg.algorithm_type
        assert alg.vendor
        assert alg.implementation_name
        assert isinstance(alg.validation_date, date)

    dgsts = {alg.dgst for alg in algs}
    assert "AES 123" in dgsts
    assert "SHS 456" in dgsts
    assert "HMAC 789" in dgsts

    assert dgst_to_pid["AES 123"] == "9999"
    assert dgst_to_pid["SHS 456"] == "9999"
    assert dgst_to_pid["HMAC 789"] == "8888"


def test_parse_product_page(product_page_html_path: Path):
    data = ProductPageData.from_html(product_page_html_path)

    assert data.description == "A test cryptographic library for unit testing purposes."
    assert data.version == "2.0.1"
    assert data.product_type == "SOFTWARE"

    validations = data.validations
    assert len(validations) == 2
    assert "AES 123" in validations
    assert "SHS 456" in validations

    aes_pairs = sorted(validations["AES 123"])
    assert aes_pairs == [
        ("AES-CBC", "Ubuntu 22.04 on x86_64"),
        ("AES-CBC", "Windows Server 2022 on x86_64"),
        ("AES-GCM", "Ubuntu 22.04 on x86_64"),
    ]

    shs_pairs = sorted(validations["SHS 456"])
    assert shs_pairs == [("SHA-256", None), ("SHA-512", None)]


def test_parse_product_page_malformed(tmp_path):
    html_path = tmp_path / "bad.html"
    html_path.write_text("<html><body><p>Not a product page</p></body></html>")

    data = ProductPageData.from_html(html_path)

    assert data.description is None
    assert data.version is None
    assert data.product_type is None
    assert data.validations == {}


def test_alg_dset_json_roundtrip_enriched(alg: FIPSAlgorithm, tmp_path):
    root_dir = tmp_path / "alg_dset"
    root_dir.mkdir()
    dset = FIPSAlgorithmDataset({alg.dgst: alg}, root_dir=root_dir)
    dset.to_json()

    assert dset.json_path is not None
    loaded = FIPSAlgorithmDataset.from_json(dset.json_path)
    assert loaded == dset
    assert loaded[alg.dgst].capability_environment_pairs == alg.capability_environment_pairs


def test_to_pandas(alg_dset: FIPSAlgorithmDataset):
    df = alg_dset.to_pandas()
    assert df.shape == (len(alg_dset), len(FIPSAlgorithm.pandas_columns) - 1)
    assert df.index.name == "dgst"
    assert set(df.columns) == set(FIPSAlgorithm.pandas_columns) - {"dgst"}


def test_serialization_missing_path():
    dummy_dset = FIPSAlgorithmDataset()
    with pytest.raises(SerializationError):
        dummy_dset.to_json()


@pytest.mark.parametrize(
    "example_id,expected_type",
    [
        (1, "HARDWARE"),
        (2, "SOFTWARE"),
        (3, "SOFTWARE"),
        (4, "HARDWARE"),
        (5, "SOFTWARE"),
    ],
)
def test_parse_product_page_with_examples(example_id: int, expected_type: str):
    html_path = Path(f"dataset/fips_algorithms/example_alg_{example_id}.html")
    if not html_path.exists():
        pytest.skip("Example HTML not available")
    data = ProductPageData.from_html(html_path)
    assert data.product_type == expected_type
    assert data.description is not None
    assert data.version is not None
    assert len(data.validations) > 0
    for pairs in data.validations.values():
        assert len(pairs) > 0


def test_from_web_mocked(alg_list_html_path: Path, product_page_html_path: Path, tmp_path):
    def mock_download_list(output_dir):
        return [alg_list_html_path]

    def mock_download_products(product_ids, output_dir):
        return dict.fromkeys(product_ids, product_page_html_path)

    with (
        patch.object(FIPSAlgorithmDataset, "download_alg_list_htmls", side_effect=mock_download_list),
        patch.object(FIPSAlgorithmDataset, "download_product_htmls", side_effect=mock_download_products),
    ):
        dset = FIPSAlgorithmDataset.from_web(root_dir=tmp_path)

    assert len(dset) == 3
    for alg in dset.algs.values():
        assert isinstance(alg.validation_date, date)
        assert alg.product_id is not None
        assert alg.description == "A test cryptographic library for unit testing purposes."
        assert alg.version == "2.0.1"
        assert alg.product_type == "SOFTWARE"

    aes_alg = dset["AES 123"]
    assert aes_alg.capability_environment_pairs is not None
    assert len(aes_alg.capability_environment_pairs) == 3


@pytest.mark.parametrize("text", ["", "123", "AES", "   ", "!!!", "  456  "])
def test_parse_alg_type_and_number_invalid(text: str):
    assert _parse_alg_type_and_number(text) is None


def test_parse_alg_type_and_number_valid():
    assert _parse_alg_type_and_number("AES 123") == ("AES", "123")
    assert _parse_alg_type_and_number("HMAC789") == ("HMAC", "789")


def test_from_html_unreadable_file(tmp_path):
    bad_path = tmp_path / "nonexistent.html"
    data = ProductPageData.from_html(bad_path)
    assert data == ProductPageData()


def test_from_html_parse_exception(tmp_path, monkeypatch):
    html_path = tmp_path / "page.html"
    html_path.write_text("<html><body></body></html>")

    def raise_on_parse(soup):
        raise RuntimeError("boom")

    monkeypatch.setattr(ProductPageData, "_parse_description", raise_on_parse)
    data = ProductPageData.from_html(html_path)
    assert data == ProductPageData()


def test_parse_validations_skips_form_without_validation_link(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <form method="get"><h4><a href="other">Not a validation</a></h4></form>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.validations == {}


def test_parse_validations_skips_unparseable_alg_text(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <form method="get">
        <h4><a href="details?validation=1">!!!</a></h4>
    </form>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.validations == {}


def test_parse_description_no_padrow(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <div id="product-version">1.0</div>
    <div id="product-type">SOFTWARE</div>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.description is None
    assert data.version == "1.0"


def test_parse_description_padrow_without_description_label(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <div class="padrow">
        <div class="col-md-2">Not Description</div>
        <div class="col-md-10">Some value</div>
    </div>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.description is None


def test_parse_description_empty_value(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <div class="padrow">
        <div class="col-md-2">Description</div>
        <div class="col-md-10">   </div>
    </div>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.description is None


def test_parse_element_text_empty_value(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <div id="product-version">   </div>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.version is None


def test_parse_capability_pairs_empty_oe(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <form method="get">
        <h4><a href="details?validation=1">AES 100</a></h4>
        <table><tr>
            <td>   </td>
            <td><a href="Validation-Notes#AES-CBC"><b>AES-CBC:</b></a></td>
        </tr></table>
    </form>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.validations["AES 100"] == [("AES-CBC", None)]


def test_parse_capability_pairs_empty_cap_text(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body>
    <form method="get">
        <h4><a href="details?validation=1">AES 100</a></h4>
        <table><tr>
            <td>Linux</td>
            <td><a href="Validation-Notes#AES-CBC">  </a></td>
        </tr></table>
    </form>
    </body></html>
    """)
    data = ProductPageData.from_html(html_path)
    assert data.validations["AES 100"] == []


def test_parse_algorithms_no_table(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("<html><body><p>No table here</p></body></html>")
    algs, dgst_to_pid = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert algs == set()
    assert dgst_to_pid == {}


def test_parse_algorithms_no_tbody(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("<html><body><table><thead><tr><th>X</th></tr></thead></table></body></html>")
    algs, dgst_to_pid = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert algs == set()
    assert dgst_to_pid == {}


def test_parse_algorithms_row_with_single_cell(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body><table><tbody>
    <tr><td>only one cell</td></tr>
    </tbody></table></body></html>
    """)
    algs, _ = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert algs == set()


def test_parse_algorithms_row_without_validation_link(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body><table><tbody>
    <tr>
        <td>Vendor</td>
        <td>Impl</td>
        <td><span>no link here</span></td>
        <td>1/15/2024</td>
    </tr>
    </tbody></table></body></html>
    """)
    algs, _ = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert algs == set()


def test_parse_algorithms_impl_without_product_link(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body><table><tbody>
    <tr>
        <td>Vendor X</td>
        <td>Plain Text Impl</td>
        <td><a id="validation-number-1" href="details?validation=1">AES 999</a></td>
        <td>1/15/2024</td>
    </tr>
    </tbody></table></body></html>
    """)
    algs, dgst_to_pid = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert len(algs) == 1
    alg = next(iter(algs))
    assert alg.vendor == "Vendor X"
    assert alg.implementation_name == "Plain Text Impl"
    assert alg.dgst not in dgst_to_pid


def test_contains_non_algorithm():
    dset = FIPSAlgorithmDataset()
    with pytest.raises(ValueError, match="is not of FIPSAlgorithm class"):
        "not an algorithm" in dset


def test_enrich_alg_without_product_id():
    alg = FIPSAlgorithm(
        alg_number="1", algorithm_type="AES", vendor="V", implementation_name="I", validation_date=date(2024, 1, 1)
    )
    enriched = FIPSAlgorithmDataset._enrich_with_product_data({alg}, {}, {})
    assert enriched[alg.dgst] is alg


def test_enrich_alg_with_product_but_no_matching_validation():
    alg = FIPSAlgorithm(
        alg_number="1", algorithm_type="AES", vendor="V", implementation_name="I", validation_date=date(2024, 1, 1)
    )
    product_data = ProductPageData(description="desc", version="1.0", product_type="SW", validations={})
    enriched = FIPSAlgorithmDataset._enrich_with_product_data({alg}, {"AES 1": "pid1"}, {"pid1": product_data})
    result = enriched["AES 1"]
    assert result.description == "desc"
    assert result.capability_environment_pairs is None


def test_from_web_mocked_without_root_dir(alg_list_html_path: Path, product_page_html_path: Path):
    def mock_download_list(output_dir):
        return [alg_list_html_path]

    def mock_download_products(product_ids, output_dir):
        return dict.fromkeys(product_ids, product_page_html_path)

    with (
        patch.object(FIPSAlgorithmDataset, "download_alg_list_htmls", side_effect=mock_download_list),
        patch.object(FIPSAlgorithmDataset, "download_product_htmls", side_effect=mock_download_products),
    ):
        dset = FIPSAlgorithmDataset.from_web()

    assert len(dset) == 3
    assert dset.root_dir is None
    assert dset.json_path is None


def test_contains_true(alg: FIPSAlgorithm):
    dset = FIPSAlgorithmDataset({alg.dgst: alg})
    assert alg in dset


def test_contains_false(alg: FIPSAlgorithm):
    dset = FIPSAlgorithmDataset()
    assert alg not in dset


def test_eq_with_non_dataset(alg: FIPSAlgorithm):
    dset = FIPSAlgorithmDataset({alg.dgst: alg})
    assert dset != "not a dataset"


def test_get_number_of_html_pages(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text('<html><body><span data-total-pages="42"></span></body></html>')
    assert FIPSAlgorithmDataset.get_number_of_html_pages(html_path) == 42


def test_parse_algorithms_continuation_row(tmp_path):
    """Test 2-cell row (continuation row reusing previous vendor/impl)."""
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body><table><tbody>
    <tr>
        <td>Vendor A</td>
        <td><a id="product-name-1" href="details?product=111">Impl A</a></td>
        <td><a id="validation-number-1" href="details?validation=1">AES 100</a></td>
        <td>1/15/2024</td>
    </tr>
    <tr>
        <td><a id="validation-number-2" href="details?validation=2">SHS 200</a></td>
        <td>2/20/2024</td>
    </tr>
    </tbody></table></body></html>
    """)
    algs, dgst_to_pid = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert len(algs) == 2
    dgsts = {a.dgst for a in algs}
    assert "AES 100" in dgsts
    assert "SHS 200" in dgsts
    # continuation row inherits vendor/impl/pid
    shs = next(a for a in algs if a.dgst == "SHS 200")
    assert shs.vendor == "Vendor A"
    assert shs.implementation_name == "Impl A"
    assert dgst_to_pid.get("SHS 200") == "111"


def test_extract_product_info_no_product_param(tmp_path):
    html_path = tmp_path / "page.html"
    html_path.write_text("""
    <html><body><table><tbody>
    <tr>
        <td>Vendor</td>
        <td><a id="product-name-1" href="details?other=123">Impl</a></td>
        <td><a id="validation-number-1" href="details?validation=1">AES 100</a></td>
        <td>1/15/2024</td>
    </tr>
    </tbody></table></body></html>
    """)
    algs, dgst_to_pid = FIPSAlgorithmDataset.parse_algorithms_from_html(html_path)
    assert len(algs) == 1
    alg = next(iter(algs))
    assert alg.implementation_name == "Impl"
    assert alg.dgst not in dgst_to_pid
