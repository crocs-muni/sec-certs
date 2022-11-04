from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset


@pytest.mark.skip(reason="FIPSAlgorithmDataset yet to undergo refactoring.")
@pytest.mark.slow
def test_get_certs_from_web(self):
    with TemporaryDirectory() as tmp_dir:
        web_path = Path(tmp_dir) / "web"
        web_path.mkdir()
        aset = FIPSAlgorithmDataset({}, web_path / "algorithms", "algorithms", "sample algs")
        aset.get_certs_from_web()
