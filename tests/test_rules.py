from unittest import TestCase

from sec_certs.cert_rules import cc_rules, fips_rules


class TestRules(TestCase):
    def test_rules(self):
        assert "cc_cert_id" in cc_rules
        assert "fips_cert_id" in fips_rules
