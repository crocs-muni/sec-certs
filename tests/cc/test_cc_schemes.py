from datetime import date
from urllib.parse import urlparse

import pytest

import sec_certs.sample.cc_scheme as CCSchemes
from sec_certs.dataset.auxiliary_dataset_handling import CCSchemeDatasetHandler
from sec_certs.dataset.cc import CCDataset
from sec_certs.heuristics.cc import compute_scheme_data
from sec_certs.model.cc_matching import CCSchemeMatcher
from sec_certs.sample.cc import CCCertificate


def absolute_urls(results):
    for result in results:
        for key, value in result.items():
            if "url" in key or "link" in key and value is not None:
                parsed = urlparse(value)
                assert bool(parsed.netloc)
    return True


@pytest.mark.remote
def test_australia():
    ineval = CCSchemes.get_australia_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.fixture
def canada_certified():
    return CCSchemes.get_canada_certified()


@pytest.mark.remote
@pytest.mark.slow
def test_canada(canada_certified):
    assert len(canada_certified) != 0
    assert absolute_urls(canada_certified)
    ineval = CCSchemes.get_canada_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
@pytest.mark.slow
def test_anssi():
    certified = CCSchemes.get_france_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_france_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.remote
@pytest.mark.slow
def test_bsi():
    certified = CCSchemes.get_germany_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.remote
def test_india():
    certified = CCSchemes.get_india_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_india_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.remote
def test_italy():
    certified = CCSchemes.get_italy_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemes.get_italy_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
def test_japan():
    certified = CCSchemes.get_japan_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_japan_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemes.get_japan_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
def test_malaysia():
    certified = CCSchemes.get_malaysia_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_malaysia_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemes.get_malaysia_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
def test_netherlands():
    certified = CCSchemes.get_netherlands_certified()
    assert len(certified) != 0
    # assert absolute_urls(certified)
    ineval = CCSchemes.get_netherlands_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
def test_norway():
    certified = CCSchemes.get_norway_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_norway_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.remote
def test_korea():
    certified = CCSchemes.get_korea_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_korea_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)


@pytest.mark.remote
def test_poland():
    certified = CCSchemes.get_poland_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    ineval = CCSchemes.get_poland_ineval()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
def test_singapore():
    certified = CCSchemes.get_singapore_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_singapore_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemes.get_singapore_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
def test_spain():
    certified = CCSchemes.get_spain_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.remote
def test_sweden():
    certified = CCSchemes.get_sweden_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    archived = CCSchemes.get_sweden_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    ineval = CCSchemes.get_sweden_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)


@pytest.mark.remote
@pytest.mark.xfail(reason="Turkey's site does not exist anymore.")
def test_turkey():
    certified = CCSchemes.get_turkey_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)


@pytest.mark.remote
def test_usa():
    certified = CCSchemes.get_usa_certified()
    assert len(certified) != 0
    assert absolute_urls(certified)
    assert all(c["category"] is None or isinstance(c["category"], str) for c in certified)
    archived = CCSchemes.get_usa_archived()
    assert len(archived) != 0
    assert absolute_urls(archived)
    assert all(c["category"] is None or isinstance(c["category"], str) for c in archived)
    ineval = CCSchemes.get_usa_in_evaluation()
    assert len(ineval) != 0
    assert absolute_urls(ineval)
    assert all(c["category"] is None or isinstance(c["category"], str) for c in ineval)


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
            "certification_date": date(year=2020, month=6, day=15),
            "report_link": "https://www.fmv.se/globalassets/csec/netiq-identity-manager-4.7/certification-report---netiq-identity-manager-4.7.pdf",
            "cert_link": "https://www.fmv.se/globalassets/csec/netiq-identity-manager-4.7/certifikat-ccra---netiq-identity-manager-4.7.pdf",
            "sponsor": "NetIQ Corporation",
            "developer": "NetIQ Corporation",
            "evaluation_facility": "Combitech AB and EWA-Canada",
        },
    }
    matcher = CCSchemeMatcher(entry, "SE")
    assert matcher.match(cert_one) > 95


@pytest.mark.remote
def test_matching(toy_dataset: CCDataset, canada_certified):
    matches, scores = CCSchemeMatcher.match_all(canada_certified, "CA", toy_dataset)
    assert len(matches) == 1
    assert len(scores) == 1


def test_process_dataset(toy_dataset: CCDataset):
    toy_dataset.aux_handlers[CCSchemeDatasetHandler].only_schemes = {"CA"}  # type: ignore
    toy_dataset.aux_handlers[CCSchemeDatasetHandler].process_dataset()
    compute_scheme_data(toy_dataset.aux_handlers[CCSchemeDatasetHandler].dset, toy_dataset.certs)
    assert toy_dataset["8f08cacb49a742fb"].heuristics.scheme_data is not None
