from datetime import date

import pytest

from sec_certs.sample.pp_scheme import NIAPScraper


@pytest.mark.parametrize(
    "short_name, expected",
    [
        ("PP_APP_v1.4", "1.4"),
        ("CPP_FDE_AA_V2.0E", "2.0E"),
        ("PP_OS_CA_V1.d", "1.d"),
        ("PP_NO_VERSION", ""),
        (None, ""),
    ],
)
def test_niap_version_from_short_name(short_name, expected):
    assert NIAPScraper._niap_version_from_short_name(short_name) == expected


def test_niap_tech_type_to_cc_category():
    assert NIAPScraper._niap_tech_type_to_cc_category("Firewall") == "Boundary Protection Devices and Systems"
    assert NIAPScraper._niap_tech_type_to_cc_category("Operating System") == "Operating Systems"
    assert NIAPScraper._niap_tech_type_to_cc_category("Totally Unknown Type") == "Other Devices and Systems"


def _sample_niap_entry() -> dict:
    return {
        "pp_id": 516,
        "pp_short_name": "PP_APP_v1.4",
        "pp_name": "Protection Profile for Application Software Version 1.4",
        "tech_type": "Application Software",
        "status": "Publishing",
        "pp_date": "2020-01-06T00:00:00Z",
        "sunset_date": "2999-10-04T00:00:00Z",  # future -> deterministically active
        "pp_sponsor_id": "NIAP",
        "pp_transition": "2022-04-18T00:00:00Z",
        "cc_version": "CC:2022",
    }


def test_niap_entry_to_scheme_entry():
    files = [{"file_id": 12345, "file_mime_type": "application/pdf", "file_label": "Protection Profile"}]
    detail = {"predecessor_id__pp_short_name": "PP_APP_v1.3", "successor_id__pp_short_name": "PP_APP_v2.0"}
    rec = NIAPScraper._niap_entry_to_scheme_entry(_sample_niap_entry(), files=files, detail=detail)

    assert rec.scheme == "US"
    assert rec.category == "Other Devices and Systems"
    assert rec.status == "active"
    assert rec.name == "Protection Profile for Application Software Version 1.4"
    assert rec.version == "1.4"
    assert rec.not_valid_before == date(2020, 1, 6)
    assert rec.not_valid_after == date(2999, 10, 4)
    assert rec.pp_link.endswith("file_id=12345")
    assert rec.extra["cc_version"] == "CC:2022"
    assert rec.extra["predecessor"] == "PP_APP_v1.3"
    assert rec.extra["successor"] == "PP_APP_v2.0"


def test_niap_entry_to_scheme_entry_without_files_or_detail():
    rec = NIAPScraper._niap_entry_to_scheme_entry(_sample_niap_entry())
    assert rec.pp_link is None
    assert rec.extra["predecessor"] is None
    assert rec.extra["successor"] is None
