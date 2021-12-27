from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from sec_certs.dataset.cpe import CPEDataset


class TestCPE:
    @pytest.mark.slow
    @pytest.mark.monitor_test
    def test_from_web(self):
        with TemporaryDirectory() as tmpdir:
            dset = CPEDataset.from_web(Path(tmpdir) / "cpe.json")
        assert dset is not None
        assert "cpe:2.3:o:infineon:trusted_platform_firmware:6.40:*:*:*:*:*:*:*" in dset.cpes
