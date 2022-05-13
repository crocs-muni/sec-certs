import pytest

from sec_certs.dataset import CVEDataset
from sec_certs.sample import CVE


class TestCVE:
    @pytest.mark.slow
    @pytest.mark.monitor_test
    def test_from_web(self):
        dset = CVEDataset.from_web()
        assert dset is not None
        assert "CVE-2019-15809" in dset.cves
        assert "CVE-2017-15361" in dset.cves

    def test_from_to_dict(self):
        data = {
            "cve_id": "CVE-1999-0001",
            "vulnerable_cpes": [
                {
                    "uri": "cpe:2.3:o:freebsd:freebsd:1.0:*:*:*:*:*:*:*",
                    "title": None,
                    "start_version": None,
                    "end_version": None,
                }
            ],
            "impact": {
                "_type": "Impact",
                "base_score": 5,
                "severity": "MEDIUM",
                "explotability_score": 10,
                "impact_score": 2.9,
            },
            "published_date": "1999-12-30T05:00:00+00:00",
        }
        cve = CVE.from_dict(data)
        ret = cve.to_dict()
        assert ret == data
        other_cve = CVE.from_dict(ret)
        assert cve == other_cve
