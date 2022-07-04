from unittest import TestCase

from sec_certs.cert_rules import cc_rules


class TestRules(TestCase):
    def test_rules(self):
        print(cc_rules)
