from unittest import TestCase

import pytest

from sec_certs.dataset.common_criteria import CCSchemeDataset


class TestCCSchemes(TestCase):
    def test_australia(self):
        assert len(CCSchemeDataset.get_australia_in_evaluation()) != 0

    def test_canada(self):
        assert len(CCSchemeDataset.get_canada_certified()) != 0
        assert len(CCSchemeDataset.get_canada_in_evaluation()) != 0

    def test_anssi(self):
        assert len(CCSchemeDataset.get_france_certified()) != 0

    def test_bsi(self):
        assert len(CCSchemeDataset.get_germany_certified()) != 0

    @pytest.mark.xfail
    def test_india(self):
        assert len(CCSchemeDataset.get_india_certified()) != 0
        assert len(CCSchemeDataset.get_india_archived()) != 0

    def test_italy(self):
        assert len(CCSchemeDataset.get_italy_certified()) != 0
        assert len(CCSchemeDataset.get_italy_in_evaluation()) != 0

    def test_japan(self):
        assert len(CCSchemeDataset.get_japan_certified()) != 0
        assert len(CCSchemeDataset.get_japan_archived()) != 0
        assert len(CCSchemeDataset.get_japan_in_evaluation()) != 0

    def test_malaysia(self):
        assert len(CCSchemeDataset.get_malaysia_certified()) != 0
        assert len(CCSchemeDataset.get_malaysia_in_evaluation()) != 0

    def test_netherlands(self):
        assert len(CCSchemeDataset.get_netherlands_certified()) != 0
        assert len(CCSchemeDataset.get_netherlands_in_evaluation()) != 0

    def test_norway(self):
        assert len(CCSchemeDataset.get_norway_certified()) != 0
        assert len(CCSchemeDataset.get_norway_archived()) != 0

    def test_korea(self):
        assert len(CCSchemeDataset.get_korea_certified()) != 0
        CCSchemeDataset.get_korea_suspended()
        assert len(CCSchemeDataset.get_korea_archived()) != 0

    def test_singapore(self):
        assert len(CCSchemeDataset.get_singapore_certified()) != 0
        assert len(CCSchemeDataset.get_singapore_archived()) != 0
        assert len(CCSchemeDataset.get_singapore_in_evaluation()) != 0

    def test_spain(self):
        assert len(CCSchemeDataset.get_spain_certified()) != 0

    def test_sweden(self):
        assert len(CCSchemeDataset.get_sweden_certified()) != 0
        assert len(CCSchemeDataset.get_sweden_in_evalution()) != 0
        assert len(CCSchemeDataset.get_sweden_archived()) != 0

    def test_turkey(self):
        assert len(CCSchemeDataset.get_turkey_certified()) != 0

    def test_usa(self):
        assert len(CCSchemeDataset.get_usa_certified()) != 0
        assert len(CCSchemeDataset.get_usa_in_evaluation()) != 0
        assert len(CCSchemeDataset.get_usa_archived()) != 0
