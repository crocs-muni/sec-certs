from unittest import TestCase

import pytest

from sec_certs.dataset.cve import CVEDataset


class TestCVE(TestCase):
    @pytest.mark.slow
    def test_from_web(self):
        dset = CVEDataset.from_web()
        assert dset is not None
        assert "CVE-2019-15809" in dset.cves
        assert "CVE-2017-15361" in dset.cves
