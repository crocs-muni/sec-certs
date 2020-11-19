import csv
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from sec_certs.download import download_cc_web, download_fips_web, download_cc


class BasicTests(TestCase):
    def setUp(self):
        self.test_data_dir = Path(__file__).parent / "data"

    def test_download(self):
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            download_cc_web(tmp_path, 4)
            cc_files = {"cc_products_active.html", "cc_products_archived.html", "cc_labs.html",
                        "cc_products_active.csv", "cc_products_archived.csv", "cc_pp_active.html",
                        "cc_pp_collaborative.html", "cc_pp_archived.html", "cc_pp_active.csv",
                        "cc_pp_archived.csv"}
            actual = {path.name for path in tmp_path.iterdir()}
            self.assertEqual(cc_files, actual)

        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            download_fips_web(tmp_path)
            fips_files = {'fips_modules_active.html',
                          'fips_modules_historical.html',
                          'fips_modules_revoked.html'}
            actual = {path.name for path in tmp_path.iterdir()}
            self.assertEqual(fips_files, actual)

    def test_full_cc_download(self):
        with open(self.test_data_dir / "certs.csv") as f:
            reader = csv.DictReader(f)
            certs = [(row["cert"], row["st"]) for row in reader]
        cert_list = [("/epfiles/" + cert, cert, "/epfiles/" + st, st) for cert, st in certs]
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            (tmp_path / "certs").mkdir()
            (tmp_path / "targets").mkdir()
            download_cc(tmp_path, cert_list, 4)
            actual = {path.name for path in tmp_path.iterdir()}
            print(actual)
