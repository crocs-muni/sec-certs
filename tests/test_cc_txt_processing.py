import tests.data.test_cc_heuristics
from unittest import TestCase
from pathlib import Path
from typing import ClassVar
import tempfile
import shutil

from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.sample.common_criteria import CommonCriteriaCert


class TestCommonCriteriaHeuristics(TestCase):
    dataset_json_path: ClassVar[Path] = Path(tests.data.test_cc_heuristics.__path__[0]) / 'vulnerable_dataset.json'
    data_dir_path: ClassVar[Path] = dataset_json_path.parent

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir: ClassVar[tempfile.TemporaryDirectory] = tempfile.TemporaryDirectory()
        shutil.copytree(cls.data_dir_path, cls.tmp_dir.name, dirs_exist_ok=True)

        cls.cc_dset: CCDataset = CCDataset.from_json(Path(cls.tmp_dir.name) / 'vulnerable_dataset.json')
        cls.cc_dset.download_all_pdfs()
        cls.cc_dset.convert_all_pdfs()

    def test_extract_frontpage(self):
        subject_cert: CommonCriteriaCert = list(self.cc_dset.certs.values())[0]

        subject_cert.state.st_extract_ok = True
        CommonCriteriaCert.extract_st_pdf_frontpage(subject_cert)
        self.assertTrue(subject_cert.state.st_extract_ok, True)

        subject_cert.state.report_extract_ok = True
        CommonCriteriaCert.extract_report_pdf_frontpage(subject_cert)
        self.assertTrue(subject_cert.state.report_extract_ok, True)

    def test_keyword_extraction(self):
        subject_cert: CommonCriteriaCert = list(self.cc_dset.certs.values())[0]

        subject_cert.state.st_extract_ok = True
        CommonCriteriaCert.extract_st_pdf_keywords(subject_cert)
        self.assertTrue(subject_cert.state.st_extract_ok, True)

        subject_cert.state.report_extract_ok = True
        CommonCriteriaCert.extract_report_pdf_keywords(subject_cert)
        self.assertTrue(subject_cert.state.report_extract_ok, True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp_dir.cleanup()
