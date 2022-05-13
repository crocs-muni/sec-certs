from pathlib import Path
from typing import ClassVar
from unittest import TestCase

from sec_certs.dataset import IUTDataset
from sec_certs.sample import IUTSnapshot


class TestFIPSIUT(TestCase):
    test_data_dir: ClassVar[Path] = Path(__file__).parent / "data" / "test_fips_iut"
    test_data_dump: ClassVar[Path] = test_data_dir / "fips_iut_2020-10-25T06+01:00.html"

    def test_from_dumps(self):
        dset = IUTDataset.from_dumps(self.test_data_dir)
        self.assertIsNotNone(dset)
        self.assertEqual(len(dset), 2)

    def test_from_dump(self):
        snap = IUTSnapshot.from_dump(self.test_data_dump)
        self.assertIsNotNone(snap)

    def test_from_web(self):
        snap = IUTSnapshot.from_web()
        self.assertIsNotNone(snap)
