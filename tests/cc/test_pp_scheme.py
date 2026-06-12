from datetime import date

import pytest

from sec_certs.configuration import config
from sec_certs.model.pp_matching import PPSchemeMatcher
from sec_certs.sample.pp_scheme import NIAPScraper, PPSchemeRecord
from sec_certs.sample.protection_profile import ProtectionProfile


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


def _make_record(**overrides) -> PPSchemeRecord:
    fields = {
        "category": "C",
        "status": "active",
        "is_collaborative": False,
        "name": "N",
        "version": "1.0",
        "security_level": set(),
        "not_valid_before": None,
        "not_valid_after": None,
        "report_link": None,
        "pp_link": None,
        "scheme": "US",
    }
    fields.update(overrides)
    return PPSchemeRecord(**fields)


def test_to_enrichment_dict():
    rec = _make_record(extra={"pp_short_name": "PP_X_v1.0", "predecessor": "PP_X_v0.9"})
    assert rec.to_enrichment_dict() == {
        "source_scheme": "US",
        "pp_short_name": "PP_X_v1.0",
        "predecessor": "PP_X_v0.9",
    }


def test_record_from_dict_parses_dates_and_maintenances():
    dct = {
        "category": "C",
        "status": "archived",
        "is_collaborative": True,
        "name": "N",
        "version": "1.0",
        "security_level": set(),
        "not_valid_before": "2020-01-06",
        "not_valid_after": "2021-02-07",
        "report_link": None,
        "pp_link": None,
        "scheme": "US",
        "maintenances": [["2020-05-05", "maint", "http://x"]],
        "extra": {"k": "v"},
    }
    rec = PPSchemeRecord.from_dict(dct)
    assert rec.not_valid_before == date(2020, 1, 6)
    assert rec.not_valid_after == date(2021, 2, 7)
    assert rec.maintenances == [("2020-05-05", "maint", "http://x")]
    assert rec.extra == {"k": "v"}


def _make_pp(**overrides) -> ProtectionProfile:
    fields = {
        "category": "C",
        "status": "active",
        "is_collaborative": False,
        "name": "Foo Protection Profile",
        "version": "1.0",
        "security_level": set(),
        "not_valid_before": date(2020, 1, 1),
        "not_valid_after": None,
        "report_link": None,
        "pp_link": "https://niap/foo.pdf",
        "scheme": "US",
        "maintenances": [],
    }
    fields.update(overrides)
    return ProtectionProfile(ProtectionProfile.WebData(**fields))


def test_single_match_by_pp_link():
    pp = _make_pp()
    rec = _make_record(name="Anything", pp_link="https://niap/foo.pdf")
    assert PPSchemeMatcher(rec).match(pp) == 100.0


def test_single_match_by_name_and_date():
    pp = _make_pp(pp_link="https://cc/foo.pdf")
    rec = _make_record(name="Foo Protection Profile", not_valid_before=date(2020, 1, 1))
    assert PPSchemeMatcher(rec).match(pp) > config.pp_matching_threshold


def test_single_match_below_threshold():
    pp = _make_pp(pp_link="https://cc/foo.pdf", name="Alpha", not_valid_before=date(1999, 12, 31))
    rec = _make_record(name="Zulu", not_valid_before=date(2020, 1, 1))
    assert PPSchemeMatcher(rec).match(pp) < config.pp_matching_threshold
