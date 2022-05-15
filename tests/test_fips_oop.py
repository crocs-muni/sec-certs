import shutil
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, Final, List
from unittest import TestCase

import tests.data.test_fips_oop
from sec_certs.config.configuration import config
from sec_certs.dataset import FIPSAlgorithmDataset, FIPSDataset
from sec_certs.helpers import fips_dgst
from tests.fips_test_utils import generate_html


def _set_up_dataset(td, certs):
    dataset = FIPSDataset({}, Path(td), "test_dataset", "fips_test_dataset")
    generate_html(certs, td + "/test_search.html")
    dataset.get_certs_from_web(test=td + "/test_search.html", no_download_algorithms=True)
    return dataset


def _set_up_dataset_for_full(td, certs, cpe_dset_path: Path, cve_dset_path: Path):
    dataset = _set_up_dataset(td, certs)

    dataset.auxillary_datasets_dir.mkdir(exist_ok=True)
    shutil.copyfile(cpe_dset_path, dataset.cpe_dataset_path)
    shutil.copyfile(cve_dset_path, dataset.cve_dataset_path)

    dataset.web_scan(set(certs))
    dataset.download_all_pdfs(set(certs))
    dataset.convert_all_pdfs()
    dataset.pdf_scan()
    dataset.extract_certs_from_tables(high_precision=True)
    dataset.algorithms = FIPSAlgorithmDataset.from_json(Path(__file__).parent / "data/test_fips_oop/algorithms.json")
    dataset.finalize_results(use_nist_cpe_matching_dict=False, perform_cpe_heuristics=False)
    return dataset


class TestFipsOOP(TestCase):
    data_dir: Final[Path] = Path(tests.data.test_fips_oop.__path__[0])
    cpe_dset_path: Final[Path] = data_dir.parent / "test_cc_heuristics/auxillary_datasets/cpe_dataset.json"
    cve_dset_path: Final[Path] = data_dir.parent / "test_cc_heuristics/auxillary_datasets/cve_dataset.json"
    certs_to_parse: Final[Dict[str, List[str]]] = {
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

    @classmethod
    def setUpClass(cls) -> None:
        config.load(cls.data_dir.parent / "settings_test.yaml")

    def test_regress_125(self):
        with TemporaryDirectory() as tmp_dir:
            dst = _set_up_dataset(tmp_dir, ["3493", "3495"])
            self.assertEqual(set(dst.certs), {fips_dgst("3493"), fips_dgst("3495")})
            self.assertIsInstance(dst.certs[fips_dgst("3493")].cert_id, int)
            self.assertEqual(dst.certs[fips_dgst("3493")].cert_id, 3493)

    def test_size(self):
        for certs in self.certs_to_parse.values():
            with TemporaryDirectory() as tmp_dir:
                dataset = _set_up_dataset(tmp_dir, certs)
                self.assertEqual(len(dataset.certs), len(certs), "Wrong number of parsed certs")

    def test_connections_microsoft(self):
        certs = self.certs_to_parse["microsoft"]
        with TemporaryDirectory() as tmp_dir:
            dataset = _set_up_dataset_for_full(tmp_dir, certs, self.cpe_dset_path, self.cve_dset_path)

            self.assertEqual(
                set(dataset.certs[fips_dgst("3095")].heuristics.st_references.directly_referencing), {"3096"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3095")].heuristics.web_references.directly_referencing),
                {"3093", "3096", "3094"},
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3651")].heuristics.st_references.directly_referencing), {"3615"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3093")].heuristics.st_references.directly_referencing), {"3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3093")].heuristics.web_references.directly_referencing), {"3090", "3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3090")].heuristics.st_references.directly_referencing), {"3089"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3197")].heuristics.web_references.directly_referencing),
                {"3195", "3096", "3196", "3644", "3651"},
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3196")].heuristics.st_references.directly_referencing), {"3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3196")].heuristics.web_references.directly_referencing),
                {"3194", "3091", "3480", "3615"},
            )
            self.assertIsNone(dataset.certs[fips_dgst("3089")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("3195")].heuristics.st_references.directly_referencing), {"3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3195")].heuristics.web_references.directly_referencing),
                {"3194", "3091", "3480"},
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3480")].heuristics.st_references.directly_referencing), {"3089"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3615")].heuristics.st_references.directly_referencing), {"3089"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3194")].heuristics.st_references.directly_referencing), {"3089"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3091")].heuristics.st_references.directly_referencing), {"3089"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3690")].heuristics.st_references.directly_referencing), {"3651"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3690")].heuristics.web_references.directly_referencing),
                {"3644", "3196", "3651"},
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3644")].heuristics.st_references.directly_referencing), {"3615"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3527")].heuristics.st_references.directly_referencing), {"3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3527")].heuristics.web_references.directly_referencing), {"3090", "3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3094")].heuristics.st_references.directly_referencing), {"3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3544")].heuristics.st_references.directly_referencing), {"3096"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3544")].heuristics.web_references.directly_referencing),
                {"3093", "3096", "3527"},
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3096")].heuristics.st_references.directly_referencing), {"3091"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3096")].heuristics.web_references.directly_referencing),
                {"3090", "3194", "3091", "3480"},
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3092")].heuristics.web_references.directly_referencing),
                {"3093", "3195", "3096", "3644", "3651"},
            )

    def test_connections_redhat(self):
        certs = self.certs_to_parse["redhat"]
        with TemporaryDirectory() as tmp_dir:
            dataset = _set_up_dataset_for_full(tmp_dir, certs, self.cpe_dset_path, self.cve_dset_path)
            self.assertEqual(
                set(dataset.certs[fips_dgst("2630")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2633")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertIsNone(dataset.certs[fips_dgst("2441")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("2997")].heuristics.st_references.directly_referencing), {"2711"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2446")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2447")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3733")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertIsNone(dataset.certs[fips_dgst("2441")].heuristics.st_references.directly_referencing)
            self.assertIsNone(dataset.certs[fips_dgst("2711")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("2908")].heuristics.st_references.directly_referencing), {"2711"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3613")].heuristics.st_references.directly_referencing), {"2997"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2721")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2721")].heuristics.web_references.directly_referencing), {"2441", "2711"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2798")].heuristics.st_references.directly_referencing), {"2721"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2798")].heuristics.web_references.directly_referencing), {"2711", "2721"}
            )
            self.assertIsNone(dataset.certs[fips_dgst("2711")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("2997")].heuristics.st_references.directly_referencing), {"2711"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2742")].heuristics.st_references.directly_referencing), {"2721"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2742")].heuristics.web_references.directly_referencing), {"2721", "2711"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2721")].heuristics.st_references.directly_referencing), {"2441"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2721")].heuristics.web_references.directly_referencing), {"2441", "2711"}
            )

    def test_docusign_chunk(self):
        certs = self.certs_to_parse["docusign"]
        with TemporaryDirectory() as tmp_dir:
            dataset = _set_up_dataset_for_full(tmp_dir, certs, self.cpe_dset_path, self.cve_dset_path)
            self.assertEqual(
                set(dataset.certs[fips_dgst("3850")].heuristics.st_references.directly_referencing), {"1883"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3850")].heuristics.web_references.directly_referencing), {"1883"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2779")].heuristics.st_references.directly_referencing), {"1883"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2860")].heuristics.st_references.directly_referencing), {"1883"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2665")].heuristics.st_references.directly_referencing), {"1883"}
            )
            self.assertIsNone(dataset.certs[fips_dgst("1883")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("3518")].heuristics.st_references.directly_referencing), {"1883"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3141")].heuristics.st_references.directly_referencing), {"1883"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2590")].heuristics.st_references.directly_referencing), {"1883"}
            )

    def test_openssl_chunk(self):
        certs = self.certs_to_parse["referencing_openssl"]
        with TemporaryDirectory() as tmp_dir:
            dataset = _set_up_dataset_for_full(tmp_dir, certs, self.cpe_dset_path, self.cve_dset_path)
            self.assertEqual(
                set(dataset.certs[fips_dgst("3493")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3495")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3711")].heuristics.st_references.directly_referencing), {"3220"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3176")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3488")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3126")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3126")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3126")].heuristics.web_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3269")].heuristics.st_references.directly_referencing), {"3220"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3524")].heuristics.st_references.directly_referencing), {"3220"}
            )
            self.assertIsNone(dataset.certs[fips_dgst("3220")].heuristics.st_references.directly_referencing)
            self.assertIsNone(dataset.certs[fips_dgst("3220")].heuristics.web_references.directly_referencing)
            self.assertIsNone(dataset.certs[fips_dgst("2398")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("3543")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("2676")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3313")].heuristics.st_references.directly_referencing), {"3220"}
            )
            self.assertIsNone(dataset.certs[fips_dgst("3363")].heuristics.st_references.directly_referencing)
            self.assertEqual(
                set(dataset.certs[fips_dgst("3608")].heuristics.st_references.directly_referencing), {"2398"}
            )
            self.assertEqual(
                set(dataset.certs[fips_dgst("3158")].heuristics.st_references.directly_referencing), {"2398"}
            )
