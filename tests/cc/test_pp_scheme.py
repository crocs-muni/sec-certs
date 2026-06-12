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
