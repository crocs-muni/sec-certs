from sec_certs.cert_rules import cc_rules, fips_rules, rules


def test_rules():
    assert "cc_cert_id" in cc_rules
    assert "fips_cert_id" in fips_rules
    for rule_group in rules:
        if rule_group not in ("cc_rules", "fips_rules"):
            assert rule_group in cc_rules or rule_group in fips_rules
