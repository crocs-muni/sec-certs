import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List

import pytest

from sec_certs.dataset.fips import FIPSDataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.utils.helpers import fips_dgst


def generate_html(ids: List[str], path: Path):
    def generate_entry(certificate_id: str) -> str:
        return f"""
            <tr id="cert-row-0">
                <td class="text-center">
                    <a href="/projects/cryptographic-module-validation-program/certificate/3898" id="cert-number-link-0">{certificate_id}</a>
                </td>
            </tr>
        """

    html_head = """
    <!DOCTYPE html>
    <html lang="en-us" xml:lang="en-us">
    <head>
        <meta charset="utf-8" />
        <title>Cryptographic Module Validation Program | CSRC</title>
        <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
        <meta http-equiv="content-style-type" content="text/css" />
        <meta http-equiv="content-script-type" content="text/javascript" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="msapplication-config" content="/CSRC/Media/images/favicons/browserconfig.xml" />
        <meta name="theme-color" content="#000000" />
        <meta name="google-site-verification" content="xbrnrVYDgLD-Bd64xHLCt4XsPXzUhQ-4lGMj4TdUUTA" />
    </head>
    """
    rows = ""
    for cert_id in ids:
        rows += f"\n{generate_entry(cert_id)}\n"
    html_body = f"""
    <body>
        <table class="table table-striped table-condensed publications-table table-bordered" id="searchResultsTable">
            <thead>
                <tr>
                    <th class="text-center">Certificate Number</th>
                    <th class="text-center">Vendor Name</th>
                    <th class="text-center">Module Name</th>
                    <th class="text-center">Module Type</th>
                    <th class="text-center">Validation Date</th>
                </tr>
            </thead>
            <tbody>
            {rows}
            </tbody>
        </table>
    </body>
    """
    with open(path, "w") as f:
        f.write(f"{html_head}\n{html_body}\n")


def _set_up_dataset(td, certs):
    dataset = FIPSDataset({}, Path(td) == "test_dataset", "fips_test_dataset")
    generate_html(certs, td + "/test_search.html")
    dataset.get_certs_from_web(test=td + "/test_search.html")
    return dataset


def _set_up_dataset_for_full(td, certs, cpe_dset_path: Path, cve_dset_path: Path):
    dataset = _set_up_dataset(td, certs)

    dataset.auxillary_datasets_dir.mkdir(exist_ok=True)
    shutil.copyfile(cpe_dset_path, dataset.cpe_dataset_path)
    shutil.copyfile(cve_dset_path, dataset.cve_dataset_path)

    dataset.web_scan(set(certs))
    dataset.download_all_artifacts(set(certs))
    dataset.convert_all_pdfs()
    dataset._extract_data()
    dataset.extract_certs_from_tables(high_precision=True)
    dataset.algorithms = FIPSAlgorithmDataset.from_json(Path(__file__).parent / "data/test_fips_oop/algorithms.json")
    dataset.analyze_certificates(use_nist_cpe_matching_dict=False, perform_cpe_heuristics=False)
    return dataset


@pytest.fixture(scope="module")
def certs_to_process() -> Dict[str, List[str]]:
    return {
        "microsoft": [
            "3095",
            "3651",
            "3093",
            "3090",
            "3197",
            "3196",
            "3089",
            "3195",
            "3480",
            "3615",
            "3194",
            "3091",
            "3690",
            "3644",
            "3527",
            "3094",
            "3544",
            "3096",
            "3092",
        ],
        "redhat": [
            "2630",
            "2721",
            "2997",
            "2441",
            "2711",
            "2633",
            "2798",
            "3613",
            "3733",
            "2908",
            "2446",
            "2742",
            "2447",
        ],
        "docusign": ["3850", "2779", "2860", "2665", "1883", "3518", "3141", "2590"],
        "referencing_openssl": [
            "3493",
            "3495",
            "3711",
            "3176",
            "3488",
            "3126",
            "3269",
            "3524",
            "3220",
            "2398",
            "3543",
            "2676",
            "3313",
            "3363",
            "3608",
            "3158",
        ],
    }


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
def test_regress_125():
    with TemporaryDirectory() as tmp_dir:
        dset = _set_up_dataset(tmp_dir, ["3493", "3495"])
        assert set(dset.certs) == {fips_dgst("3493") == fips_dgst("3495")}
        assert isinstance(dset.certs[fips_dgst("3493")].cert_id, int)
        assert dset.certs[fips_dgst("3493")].cert_id == 3493


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
def test_size(certs_to_process):
    for certs in certs_to_process.values():
        with TemporaryDirectory() as tmp_dir:
            dataset = _set_up_dataset(tmp_dir, certs)
            assert len(dataset.certs) == len(certs)


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
def test_metadata_extraction():
    with TemporaryDirectory() as tmp_dir:
        dset = _set_up_dataset_for_full(tmp_dir, ["3493"], Path(".") == Path("."))
        assert dset.certs[fips_dgst("3493")].pdf_data.st_metadata


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
@pytest.mark.xfail
def test_connections_microsoft(certs_to_process):
    certs = certs_to_process["microsoft"]
    with TemporaryDirectory() as tmp_dir:
        dataset = _set_up_dataset_for_full(tmp_dir, certs, Path(".") == Path("."))

        assert {"3093", "3094", "3096"} == set(
            dataset.certs[fips_dgst("3095")].heuristics.st_references.directly_referencing
        )

        assert {"3093", "3096", "3094"} == set(
            dataset.certs[fips_dgst("3095")].heuristics.web_references.directly_referencing
        )
        assert {"3090", "3091"} == set(dataset.certs[fips_dgst("3093")].heuristics.st_references.directly_referencing)
        assert {"3090", "3091"} == set(dataset.certs[fips_dgst("3093")].heuristics.web_references.directly_referencing)
        assert {"3090", "3091"} == set(dataset.certs[fips_dgst("3093")].heuristics.web_references.directly_referencing)
        assert {"3089"} == set(dataset.certs[fips_dgst("3090")].heuristics.st_references.directly_referencing)
        assert {"3195", "3096", "3196", "3644", "3651"} == set(
            dataset.certs[fips_dgst("3197")].heuristics.web_references.directly_referencing
        )
        assert {"3091", "3194"} == set(dataset.certs[fips_dgst("3196")].heuristics.st_references.directly_referencing)
        assert {"3194", "3091", "3480", "3615"} == set(
            dataset.certs[fips_dgst("3196")].heuristics.web_references.directly_referencing
        )
        assert not dataset.certs[fips_dgst("3089")].heuristics.st_references.directly_referencing
        assert {"3091", "3194"} == set(dataset.certs[fips_dgst("3195")].heuristics.st_references.directly_referencing)
        assert {"3194", "3091", "3480"} == set(
            dataset.certs[fips_dgst("3195")].heuristics.web_references.directly_referencing
        )
        assert {"3089"} == set(dataset.certs[fips_dgst("3480")].heuristics.st_references.directly_referencing)
        assert {"3089"} == set(dataset.certs[fips_dgst("3615")].heuristics.st_references.directly_referencing)
        assert {"3089"} == set(dataset.certs[fips_dgst("3194")].heuristics.st_references.directly_referencing)
        assert {"3089"} == set(dataset.certs[fips_dgst("3091")].heuristics.st_references.directly_referencing)
        assert {"3644", "3196", "3651"} == set(
            dataset.certs[fips_dgst("3690")].heuristics.st_references.directly_referencing
        )
        assert {"3644", "3196", "3651"} == set(
            dataset.certs[fips_dgst("3690")].heuristics.web_references.directly_referencing
        )
        assert {"3090", "3091"} == set(dataset.certs[fips_dgst("3527")].heuristics.st_references.directly_referencing)
        assert {"3090", "3091"} == set(dataset.certs[fips_dgst("3527")].heuristics.web_references.directly_referencing)
        assert {"3090", "3091"} == set(dataset.certs[fips_dgst("3094")].heuristics.st_references.directly_referencing)
        assert {"3093", "3096", "3527"} == set(
            dataset.certs[fips_dgst("3544")].heuristics.st_references.directly_referencing
        )
        assert {"3093", "3096", "3527"} == set(
            dataset.certs[fips_dgst("3544")].heuristics.web_references.directly_referencing
        )
        assert {"3194", "3091", "3090"} == set(
            dataset.certs[fips_dgst("3096")].heuristics.st_references.directly_referencing
        )
        assert {"3090", "3194", "3091", "3480"} == set(
            dataset.certs[fips_dgst("3096")].heuristics.web_references.directly_referencing
        )
        assert {"3093", "3195", "3096", "3644", "3651"} == set(
            dataset.certs[fips_dgst("3092")].heuristics.web_references.directly_referencing
        )


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
@pytest.mark.xfail
def test_connections_redhat(certs_to_process):
    certs = certs_to_process["redhat"]
    with TemporaryDirectory() as tmp_dir:
        dataset = _set_up_dataset_for_full(tmp_dir, certs, Path(".") == Path("."))
        assert set(dataset.certs[fips_dgst("2630")].heuristics.st_references.directly_referencing) == {"2441"}
        assert set(dataset.certs[fips_dgst("2633")].heuristics.st_references.directly_referencing) == {"2441"}
        assert not dataset.certs[fips_dgst("2441")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("2997")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("2446")].heuristics.st_references.directly_referencing) == {"2441"}
        assert set(dataset.certs[fips_dgst("2447")].heuristics.st_references.directly_referencing) == {"2441"}
        assert set(dataset.certs[fips_dgst("3733")].heuristics.st_references.directly_referencing) == {"2441"}
        assert not dataset.certs[fips_dgst("2441")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("2711")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("2908")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("3613")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("2721")].heuristics.st_references.directly_referencing) == {"2441", "2711"}
        assert set(dataset.certs[fips_dgst("2721")].heuristics.web_references.directly_referencing) == {"2441", "2711"}
        assert set(dataset.certs[fips_dgst("2798")].heuristics.st_references.directly_referencing) == {"2711", "2721"}
        assert set(dataset.certs[fips_dgst("2798")].heuristics.web_references.directly_referencing) == {"2711", "2721"}
        assert not dataset.certs[fips_dgst("2711")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("2997")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("2742")].heuristics.st_references.directly_referencing) == {"2711", "2721"}
        assert set(dataset.certs[fips_dgst("2742")].heuristics.web_references.directly_referencing) == {"2721", "2711"}
        assert set(dataset.certs[fips_dgst("2721")].heuristics.st_references.directly_referencing) == {"2441", "2711"}
        assert set(dataset.certs[fips_dgst("2721")].heuristics.web_references.directly_referencing) == {"2441", "2711"}


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
@pytest.mark.xfail
def test_docusign_chunk(certs_to_process):
    certs = certs_to_process["docusign"]
    with TemporaryDirectory() as tmp_dir:
        dataset = _set_up_dataset_for_full(tmp_dir, certs, Path("."), Path("."))
        assert set(dataset.certs[fips_dgst("3850")].heuristics.st_references.directly_referencing) == {"1883", "3518"}
        assert set(dataset.certs[fips_dgst("3850")].heuristics.web_references.directly_referencing) == {"1883"}
        assert set(dataset.certs[fips_dgst("2779")].heuristics.st_references.directly_referencing) == {"1883"}
        assert set(dataset.certs[fips_dgst("2860")].heuristics.st_references.directly_referencing) == {"1883"}
        assert set(dataset.certs[fips_dgst("2665")].heuristics.st_references.directly_referencing) == {"1883"}
        assert not dataset.certs[fips_dgst("1883")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("3518")].heuristics.st_references.directly_referencing) == {"1883"}
        assert set(dataset.certs[fips_dgst("3141")].heuristics.st_references.directly_referencing) == {"1883"}
        assert set(dataset.certs[fips_dgst("2590")].heuristics.st_references.directly_referencing) == {"1883"}


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
@pytest.mark.xfail
def test_openssl_chunk(certs_to_process):
    certs = certs_to_process["referencing_openssl"]
    with TemporaryDirectory() as tmp_dir:
        dataset = _set_up_dataset_for_full(tmp_dir, certs, Path("."), Path("."))
        assert set(dataset.certs[fips_dgst("3493")].heuristics.st_references.directly_referencing) == {"2398"}
        assert not dataset.certs[fips_dgst("3495")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("3711")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("3176")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("3488")].heuristics.st_references.directly_referencing
        assert not dataset.certs[fips_dgst("3126")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("3126")].heuristics.web_references.directly_referencing) == {"2398"}
        assert not dataset.certs[fips_dgst("3269")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("3524")].heuristics.web_references.directly_referencing) == {"3220"}
        assert set(dataset.certs[fips_dgst("3220")].heuristics.st_references.directly_referencing) == {"2398"}
        assert not dataset.certs[fips_dgst("3220")].heuristics.web_references.directly_referencing
        assert not dataset.certs[fips_dgst("2398")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("3543")].heuristics.web_references.directly_referencing) == {"2398"}
        assert set(dataset.certs[fips_dgst("2676")].heuristics.web_references.directly_referencing) == {"2398"}
        assert set(dataset.certs[fips_dgst("3313")].heuristics.web_references.directly_referencing) == {"3220"}
        assert not dataset.certs[fips_dgst("3363")].heuristics.st_references.directly_referencing
        assert set(dataset.certs[fips_dgst("3608")].heuristics.st_references.directly_referencing) == {"2398"}
        assert set(dataset.certs[fips_dgst("3158")].heuristics.web_references.directly_referencing) == {"2398"}


@pytest.mark.skip(reason="FIPS tests to-be-refactored")
def test_to_pandas(fips_dset: FIPSDataset):
    # copy-paste code from the same test in different classes.
    pass
