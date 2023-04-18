from urllib.parse import urlparse

import pytest
from requests import RequestException

from sec_certs.dataset.cc import CCDataset
from sec_certs.dataset.cc_scheme import CCSchemeDataset
from sec_certs.model.cc_matching import CCSchemeMatcher
from sec_certs.sample.cc import CCCertificate


def absolute_urls(results):
    for result in results:
        for key, value in result.items():
            if "url" in key or "link" in key and value is not None:
                parsed = urlparse(value)
                assert bool(parsed.netloc)
    return True


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_australia():
    ineval = CCSchemeDataset.get_australia_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.fixture
def canada_certified():
    return CCSchemeDataset.get_canada_certified()


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_canada(canada_certified):
    assert len(canada_certified) != 0
    assert absolute_urls(canada_certified)
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
@pytest.mark.slow
def test_india():
    certified = CCSchemeDataset.get_india_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_india_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_italy():
    certified = CCSchemeDataset.get_italy_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_italy_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
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
@pytest.mark.slow
def test_malaysia():
    certified = CCSchemeDataset.get_malaysia_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_malaysia_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_netherlands():
    certified = CCSchemeDataset.get_netherlands_certified()
    assert len(certified) != 0
    # assert absolute_urls(certified)
    ineval = CCSchemeDataset.get_netherlands_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_norway():
    certified = CCSchemeDataset.get_norway_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_norway_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
def test_korea():
    certified = CCSchemeDataset.get_korea_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemeDataset.get_korea_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
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
@pytest.mark.slow
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
@pytest.mark.slow
def test_turkey():
    certified = CCSchemeDataset.get_turkey_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.xfail(reason="May fail due to server errors.", raises=RequestException)
@pytest.mark.slow
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


def test_single_match(cert_one: CCCertificate):
    entry = {
        "product": "NetIQ Identity Manager 4.7",
        "url": "https://www.fmv.se/verksamhet/ovrig-verksamhet/csec/certifikat-utgivna-av-csec/netiq-identity-manager-4.7/",
        "enhanced": {
            "title": "NetIQ Identity Manager 4.7",
            "cert_id": "CSEC2018013",
            "mutual_recognition": "CCRA, SOGIS-MRA, EA-MLA",
            "product": "NetIQ Identity Manager 4.7Software Version: Identity Applications (RBPM) 4.7.3.0.1109, Identity Manager Engine 4.7.3.0.AE, Identity Reporting Module 6.5.0. F14508F, Sentinel Log Management for Identity Governance and Administration 8.2.2.0_5415, One SSO Provider (OSP) 6.3.3.0, Self Service Password Reset (SSPR) 4.4.0.2 B366 r39762",
            "category": "Identity Manager",
            "target_link": "https://www.fmv.se/globalassets/csec/netiq-identity-manager-4.7/st---netiq-identity-manager-4.7.pdf",
            "assurance_level": "EAL3 + ALC_FLR.2",
            "certification_date": "2020-06-15",
            "report_link": "https://www.fmv.se/globalassets/csec/netiq-identity-manager-4.7/certification-report---netiq-identity-manager-4.7.pdf",
            "cert_link": "https://www.fmv.se/globalassets/csec/netiq-identity-manager-4.7/certifikat-ccra---netiq-identity-manager-4.7.pdf",
            "sponsor": "NetIQ Corporation",
            "developer": "NetIQ Corporation",
            "evaluation_facility": "Combitech AB and EWA-Canada",
        },
    }
    matcher = CCSchemeMatcher(entry, "SE")
    assert matcher.match(cert_one) > 95


def test_matching(toy_dataset: CCDataset, canada_certified):
    matches = CCSchemeMatcher.match_all(canada_certified, "CA", toy_dataset)
    assert len(matches) == 1


def test_process_dataset(toy_dataset: CCDataset):
    toy_dataset.process_schemes(True, only_schemes={"CA"})
    assert toy_dataset["8a5e6bcda602920c"].heuristics.scheme_data is not None
