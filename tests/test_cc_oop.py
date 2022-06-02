import json
import os
import shutil
import tempfile
from datetime import date, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import ClassVar
from unittest import TestCase

import sec_certs.constants as constants
import sec_certs.helpers as helpers
import tests.data.test_cc_oop
from sec_certs.config.configuration import config
from sec_certs.dataset import CCDataset
from sec_certs.sample import CommonCriteriaCert, ProtectionProfile


class TestCommonCriteriaOOP(TestCase):
    data_dir_path: ClassVar[Path] = Path(tests.data.test_cc_oop.__path__[0])

    @classmethod
    def setUpClass(cls):
        config.load(cls.data_dir_path.parent / "settings_test.yaml")

    def setUp(self):
        self.test_data_dir = Path(__file__).parent / "data" / "test_cc_oop"
        self.crt_one = CommonCriteriaCert(
            "active",
            "Access Control Devices and Systems",
            "NetIQ Identity Manager 4.7",
            "NetIQ Corporation",
            "SE",
            {"ALC_FLR.2", "EAL3+"},
            date(2020, 6, 15),
            date(2025, 6, 15),
            "https://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf",
            "https://www.commoncriteriaportal.org/files/epfiles/ST%20-%20NetIQ%20Identity%20Manager%204.7.pdf",
            "https://www.commoncriteriaportal.org/files/epfiles/Certifikat%20CCRA%20-%20NetIQ%20Identity%20Manager%204.7_signed.pdf",
            "https://www.netiq.com/",
            set(),
            set(),
            None,
            None,
            None,
        )

        self.crt_two = CommonCriteriaCert(
            "active",
            "Access Control Devices and Systems",
            "Magic SSO V4.0",
            "Dreamsecurity Co., Ltd.",
            "KR",
            set(),
            date(2019, 11, 15),
            date(2024, 11, 15),
            "https://www.commoncriteriaportal.org/files/epfiles/KECS-CR-19-70%20Magic%20SSO%20V4.0(eng)%20V1.0.pdf",
            "https://www.commoncriteriaportal.org/files/epfiles/Magic_SSO_V4.0-ST-v1.4_EN.pdf",
            None,
            "https://www.dreamsecurity.com/",
            {
                ProtectionProfile(
                    "Korean National Protection Profile for Single Sign On V1.0",
                    "https://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf",
                )
            },
            set(),
            None,
            None,
            None,
        )

        pp = ProtectionProfile("sample_pp", "https://sample.pp")
        update = CommonCriteriaCert.MaintenanceReport(
            date(1900, 1, 1), "Sample maintenance", "https://maintenance.up", "https://maintenance.up"
        )
        self.fictional_cert = CommonCriteriaCert(
            "archived",
            "Sample category",
            "Sample certificate name",
            "Sample manufacturer",
            "Sample scheme",
            {"Sample security level"},
            date(1900, 1, 2),
            date(1900, 1, 3),
            "https://path.to/report/link",
            "https://path.to/st/link",
            "https://path.to/cert/link",
            "https://path.to/manufacturer/web",
            {pp},
            {update},
            None,
            None,
            None,
        )
        self.template_dataset = CCDataset(
            {self.crt_one.dgst: self.crt_one, self.crt_two.dgst: self.crt_two},
            Path("/fictional/path/to/dataset"),
            "toy dataset",
            "toy dataset description",
        )
        self.template_dataset.timestamp = datetime(2020, 11, 16, hour=17, minute=4, second=14, microsecond=770153)
        self.template_dataset.state.meta_sources_parsed = True

        self.template_report_pdf_hashes = {
            "309ac2fd7f2dcf17": "774c41fbba980191ca40ae610b2f61484c5997417b3325b6fd68b345173bde52",
            "8cf86948f02f047d": "533a5995ef8b736cc48cfda30e8aafec77d285511471e0e5a9e8007c8750203a",
        }
        self.template_target_pdf_hashes = {
            "309ac2fd7f2dcf17": "b9a45995d9e40b2515506bbf5945e806ef021861820426c6d0a6a074090b47a9",
            "8cf86948f02f047d": "3c8614338899d956e9e56f1aa88d90e37df86f3310b875d9d14ec0f71e4759be",
        }

        self.template_report_txt_path = self.test_data_dir / "report_309ac2fd7f2dcf17.txt"
        self.template_target_txt_path = self.test_data_dir / "target_309ac2fd7f2dcf17.txt"

    def test_certificate_input_sanity(self):
        self.assertEqual(
            self.crt_one.report_link,
            "https://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf",
            "Report link contains some improperly escaped characters.",
        )

    def test_download_and_convert_pdfs(self):
        dset = CCDataset.from_json(self.test_data_dir / "toy_dataset.json")

        with TemporaryDirectory() as td:
            dset.root_dir = Path(td)
            dset.download_all_pdfs()
            dset.convert_all_pdfs()

            actual_report_pdf_hashes = {
                key: helpers.get_sha256_filepath(val.state.report_pdf_path) for key, val in dset.certs.items()
            }
            actual_target_pdf_hashes = {
                key: helpers.get_sha256_filepath(val.state.st_pdf_path) for key, val in dset.certs.items()
            }

            self.assertEqual(
                actual_report_pdf_hashes,
                self.template_report_pdf_hashes,
                "Hashes of downloaded pdfs (sample report) do not the template",
            )
            self.assertEqual(
                actual_target_pdf_hashes,
                self.template_target_pdf_hashes,
                "Hashes of downloaded pdfs (security target) do not match the template",
            )

            self.assertTrue(dset["309ac2fd7f2dcf17"].state.report_txt_path.exists())
            self.assertTrue(dset["309ac2fd7f2dcf17"].state.st_txt_path.exists())

            self.assertAlmostEqual(
                dset["309ac2fd7f2dcf17"].state.st_txt_path.stat().st_size,
                self.template_target_txt_path.stat().st_size,
                delta=1000,
            )

            self.assertAlmostEqual(
                dset["309ac2fd7f2dcf17"].state.report_txt_path.stat().st_size,
                self.template_report_txt_path.stat().st_size,
                delta=1000,
            )

    def test_cert_to_json(self):
        with NamedTemporaryFile("w") as tmp:
            self.fictional_cert.to_json(tmp.name)
            with open(tmp.name) as f:
                out = json.load(f)
            with open(self.test_data_dir / "fictional_cert.json") as f:
                template = json.load(f)
            self.assertEqual(out, template, "Serialized cert differs from cert json template.")

    def test_dataset_to_json(self):
        with NamedTemporaryFile("w") as tmp:
            self.template_dataset.to_json(tmp.name)
            with open(tmp.name, "r") as handle:
                out = json.load(handle)
            with open(self.test_data_dir / "toy_dataset.json") as handle:
                template = json.load(handle)
            self.assertEqual(out, template, "Serialized dataset differs from json template.")

    def test_cert_from_json(self):
        self.assertEqual(
            self.fictional_cert,
            CommonCriteriaCert.from_json(self.test_data_dir / "fictional_cert.json"),
            "The sample serialized from json differs from a template.",
        )

    def test_dataset_from_json(self):
        self.assertEqual(
            self.template_dataset,
            CCDataset.from_json(self.test_data_dir / "toy_dataset.json"),
            "The dataset serialized from json differs from a template.",
        )

    def test_build_empty_dataset(self):
        with TemporaryDirectory() as tmp_dir:
            dset = CCDataset({}, Path(tmp_dir), "sample_dataset", "sample dataset description")
            dset.get_certs_from_web(to_download=False, get_archived=False, get_active=False)
        self.assertEqual(len(dset), 0, "The dataset should contain 0 files.")

    def test_build_dataset(self):
        with TemporaryDirectory() as tmp_dir:
            dataset_path = Path(tmp_dir)
            os.mkdir(dataset_path / "web")
            shutil.copyfile(
                self.test_data_dir / "cc_products_active.csv", dataset_path / "web" / "cc_products_active.csv"
            )
            shutil.copyfile(
                self.test_data_dir / "cc_products_active.html", dataset_path / "web" / "cc_products_active.html"
            )

            dset = CCDataset({}, dataset_path, "sample_dataset", "sample dataset description")
            dset.get_certs_from_web(
                keep_metadata=False, to_download=False, get_archived=False, get_active=True, update_json=False
            )

            self.assertEqual(
                len(os.listdir(dataset_path)),
                0,
                "Meta files (csv, html) were not deleted properly albeit this was explicitly required.",
            )

        self.assertEqual(len(dset), 2, "The dataset should contain 2 files.")

        self.assertTrue(self.crt_one in dset, "The dataset does not contain the template sample.")
        self.assertEqual(dset, self.template_dataset, "The loaded dataset does not match the template dataset.")

    def test_download_csv_html_files(self):
        with TemporaryDirectory() as tmp_dir:
            dataset_path = Path(tmp_dir)
            dset = CCDataset({}, dataset_path, "sample_dataset", "sample dataset description")
            dset._download_csv_html_resources(get_active=True, get_archived=False)

            for x in dset.active_html_tuples:
                self.assertTrue(x[1].exists())
                self.assertGreaterEqual(x[1].stat().st_size, constants.MIN_CC_HTML_SIZE)
            for x in dset.active_csv_tuples:
                self.assertTrue(x[1].exists())
                self.assertGreaterEqual(x[1].stat().st_size, constants.MIN_CC_CSV_SIZE)

    def test_download_pp_dataset(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.template_dataset.root_dir = tmp_dir
            self.template_dataset.process_protection_profiles()
            self.assertTrue(self.template_dataset.pp_dataset_path.exists())
            self.assertGreaterEqual(
                self.template_dataset.pp_dataset_path.stat().st_size, constants.MIN_CC_PP_DATASET_SIZE
            )
