from pathlib import Path
from typing import ClassVar
from unittest import TestCase

import tests.data.test_cc_heuristics
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.cpe import CPEConfiguration


class TestCPEConfiguration(TestCase):
    test_data_dir: ClassVar[Path] = Path(tests.data.test_cc_heuristics.__path__[0]) / "auxillary_datasets"
    dset: CVEDataset

    @classmethod
    def setUpClass(cls) -> None:
        cls.dset = CVEDataset.from_json(cls.test_data_dir / "cpe_configuration_dataset.json")

    def test_single_platform_cpe_config(self):
        tested_cpe_config = self.dset["CVE-2010-2325"].vulnerable_cpe_configurations[0]
        cpe_list = [
            "cpe:2.3:a:ibm:websphere_application_server:7.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.1:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.2:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.3:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.4:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.5:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.6:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.7:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.8:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:7.0.0.9:*:*:*:*:*:*:*",
            "cpe:2.3:a:ibm:websphere_application_server:*:*:*:*:*:*:*:*",
        ]
        cpe_config = CPEConfiguration(
            platform="cpe:2.3:o:ibm:zos:*:*:*:*:*:*:*:*",
            cpes=cpe_list,
        )
        assert cpe_config == tested_cpe_config
