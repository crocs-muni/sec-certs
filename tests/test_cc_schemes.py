from unittest import TestCase

from sec_certs.dataset.common_criteria import CCSchemeDataset


class TestCCSchemes(TestCase):
    def test_australia(self):
        CCSchemeDataset.get_australia_in_evaluation()

    def test_canada(self):
        CCSchemeDataset.get_canada_certified()
        CCSchemeDataset.get_canada_in_evaluation()

    def test_anssi(self):
        CCSchemeDataset.get_france_certified()

    def test_bsi(self):
        CCSchemeDataset.get_germany_certified()

    def test_india(self):
        CCSchemeDataset.get_india_certified()
        CCSchemeDataset.get_india_archived()

    def test_italy(self):
        CCSchemeDataset.get_italy_certified()
        CCSchemeDataset.get_italy_in_evaluation()

    def test_japan(self):
        CCSchemeDataset.get_japan_certified()
        CCSchemeDataset.get_japan_archived()
        CCSchemeDataset.get_japan_in_evaluation()
