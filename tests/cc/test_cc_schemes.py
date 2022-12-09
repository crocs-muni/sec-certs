import pytest

from sec_certs.dataset import CCSchemeDataset


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_australia():
    assert len(CCSchemeDataset.get_australia_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_canada():
    assert len(CCSchemeDataset.get_canada_certified()) != 0
    assert len(CCSchemeDataset.get_canada_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_anssi():
    assert len(CCSchemeDataset.get_france_certified()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_bsi():
    assert len(CCSchemeDataset.get_germany_certified()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_india():
    assert len(CCSchemeDataset.get_india_certified()) != 0
    assert len(CCSchemeDataset.get_india_archived()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_italy():
    assert len(CCSchemeDataset.get_italy_certified()) != 0
    assert len(CCSchemeDataset.get_italy_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_japan():
    assert len(CCSchemeDataset.get_japan_certified()) != 0
    assert len(CCSchemeDataset.get_japan_archived()) != 0
    assert len(CCSchemeDataset.get_japan_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_malaysia():
    assert len(CCSchemeDataset.get_malaysia_certified()) != 0
    assert len(CCSchemeDataset.get_malaysia_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_netherlands():
    assert len(CCSchemeDataset.get_netherlands_certified()) != 0
    assert len(CCSchemeDataset.get_netherlands_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_norway():
    assert len(CCSchemeDataset.get_norway_certified()) != 0
    assert len(CCSchemeDataset.get_norway_archived()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_korea():
    assert len(CCSchemeDataset.get_korea_certified()) != 0
    CCSchemeDataset.get_korea_suspended()
    assert len(CCSchemeDataset.get_korea_archived()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_singapore():
    assert len(CCSchemeDataset.get_singapore_certified()) != 0
    assert len(CCSchemeDataset.get_singapore_archived()) != 0
    assert len(CCSchemeDataset.get_singapore_in_evaluation()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_spain():
    assert len(CCSchemeDataset.get_spain_certified()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_sweden():
    assert len(CCSchemeDataset.get_sweden_certified()) != 0
    assert len(CCSchemeDataset.get_sweden_in_evaluation()) != 0
    assert len(CCSchemeDataset.get_sweden_archived()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_turkey():
    assert len(CCSchemeDataset.get_turkey_certified()) != 0


@pytest.mark.xfail(reason="May fail due to server errors.")
def test_usa():
    assert len(CCSchemeDataset.get_usa_certified()) != 0
    assert len(CCSchemeDataset.get_usa_in_evaluation()) != 0
    assert len(CCSchemeDataset.get_usa_archived()) != 0
