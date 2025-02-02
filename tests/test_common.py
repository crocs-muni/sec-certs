import pytest

from sec_certs.cert_rules import cc_rules, fips_rules, rules
from sec_certs.utils.helpers import choose_lowest_eal


def test_rules():
    assert "cc_cert_id" in cc_rules
    assert "fips_cert_id" in fips_rules
    for rule_group in rules:
        if rule_group not in ("cc_rules", "fips_rules", "cc_filename_cert_id"):
            assert rule_group in cc_rules or rule_group in fips_rules


@pytest.mark.parametrize(
    "strings, expected",
    [
        ({"EAL5", "EAL4+", "EAL3", "random", "EAL7+", "EAL2"}, "EAL2"),
        ({"EAL1", "EAL1+", "EAL2", "EAL3+"}, "EAL1"),
        ({"random", "no_match"}, None),
        ({"EAL5+", "EAL6"}, "EAL5+"),
        (set(), None),
        ({"EAL100", "EAL10", "EAL20+"}, "EAL10"),
    ],
)
def test_find_min_eal(strings, expected):
    assert choose_lowest_eal(strings) == expected
