import csv
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from sec_certs.download import download_fips_web


class BasicTests(TestCase):
    def setUp(self):
        self.test_data_dir = Path(__file__).parent / "data"

    def test_download(self):
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            download_fips_web(tmp_path)
            fips_files = {'fips_modules_active.html',
                          'fips_modules_historical.html',
                          'fips_modules_revoked.html'}
            actual = {path.name for path in tmp_path.iterdir()}
            self.assertEqual(fips_files, actual)
