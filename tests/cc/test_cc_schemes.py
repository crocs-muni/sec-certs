from urllib.parse import urlparse

import pytest
from requests import RequestException

from sec_certs.dataset import CCSchemeDataset


def absolute_urls(results):
    for result in results:
        for key, value in result.items():
            if "url" in key or "link" in key and value is not None:
                parsed = urlparse(value)
                assert bool(parsed.netloc)
    return True


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_australia():
    ineval = CCSchemeDataset.get_australia_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_canada():
    certified = CCSchemeDataset.get_canada_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_canada_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_anssi():
    certified = CCSchemeDataset.get_france_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_bsi():
    certified = CCSchemeDataset.get_germany_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_india():
    certified = CCSchemeDataset.get_india_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_india_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_italy():
    certified = CCSchemeDataset.get_italy_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_italy_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_japan():
    certified = CCSchemeDataset.get_japan_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_japan_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemeDataset.get_japan_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_malaysia():
    certified = CCSchemeDataset.get_malaysia_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_malaysia_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_netherlands():
    certified = CCSchemeDataset.get_netherlands_certified()
    assert len(certified) != 0
    # assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_netherlands_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_norway():
    certified = CCSchemeDataset.get_norway_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_norway_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_korea():
    certified = CCSchemeDataset.get_korea_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_korea_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_singapore():
    certified = CCSchemeDataset.get_singapore_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_singapore_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemeDataset.get_singapore_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_spain():
    certified = CCSchemeDataset.get_spain_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_sweden():
    certified = CCSchemeDataset.get_sweden_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_sweden_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemeDataset.get_sweden_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_turkey():
    certified = CCSchemeDataset.get_turkey_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
def test_usa():
    certified = CCSchemeDataset.get_usa_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_usa_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemeDataset.get_usa_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)
