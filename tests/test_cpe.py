from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from sec_certs.dataset import CPEDataset
from sec_certs.sample import CPE


class TestCPE:
    @pytest.mark.slow
    @pytest.mark.monitor_test
    def test_from_web(self):
        with TemporaryDirectory() as tmpdir:
            dset = CPEDataset.from_web(Path(tmpdir) / "cpe.json")
        assert dset is not None
        assert "cpe:2.3:o:infineon:trusted_platform_firmware:6.40:*:*:*:*:*:*:*" in dset.cpes

    def test_from_to_dict(self):
        data = {
            "uri": "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*",
            "title": None,
            "start_version": None,
            "end_version": None,
        }
        cpe = CPE.from_dict(data)
        ret = cpe.to_dict()
        assert data == ret
        other_cpe = CPE.from_dict(ret)
        assert cpe == other_cpe
