from pathlib import Path
from typing import ClassVar
from unittest import TestCase

from sec_certs.dataset import MIPDataset
from sec_certs.sample import MIPSnapshot


class TestFIPSMIP(TestCase):
    test_data_dir: ClassVar[Path] = Path(__file__).parent / "data" / "test_fips_mip"
    test_data_dump: ClassVar[Path] = test_data_dir / "fips_mip_2021-02-19T06+01:00.html"

    def test_from_dumps(self):
        dset = MIPDataset.from_dumps(self.test_data_dir)
        self.assertIsNotNone(dset)
        self.assertEqual(len(dset), 3)

    def test_from_dump(self):
        snap = MIPSnapshot.from_dump(self.test_data_dump)
        self.assertIsNotNone(snap)

    def test_from_web(self):
        snap = MIPSnapshot.from_web()
        self.assertIsNotNone(snap)
