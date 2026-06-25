import pytest
from sec_certs_page.cc.search import CCSearch
from sec_certs_page.eucc.search import EUCCSearch
from sec_certs_page.fips.search import FIPSSearch
from sec_certs_page.pp.search import PPSearch
from sec_certs_page.vuln.search import CPESearch, CVESearch

SEVERITY_MEDIUM = format(1 << 2, "x")
SEVERITY_CRITICAL = format(1 << 0, "x")

CASES = [
    ("cc-id", CCSearch, {"cert_id": "BSI-DSZ-CC-1091-2018"}, {"expect_ids": {"3d1b01ce576f605d"}, "broadened": False}),
    ("cc-id-status-excludes", CCSearch, {"cert_id": "BSI-DSZ-CC-1091-2018", "status": "active"}, {"expect_ids": set()}),
    (
        "cc-name-prefix-broadens",
        CCSearch,
        {"query": "verido", "search_type": "name"},
        {"expect_ids": {"3d1b01ce576f605d"}, "broadened": True},
    ),
    ("fips-id", FIPSSearch, {"cert_id": "310"}, {"expect_ids": {"226f76b55acb4970"}, "broadened": False}),
    ("fips-id-status-excludes", FIPSSearch, {"cert_id": "310", "status": "active"}, {"expect_ids": set()}),
    (
        "pp-name",
        PPSearch,
        {"query": "ANSSI-CC-PP-2018/03", "search_type": "name"},
        {"expect_ids": {"477fa2c9a8069ca7"}},
    ),
    (
        "pp-name-status-excludes",
        PPSearch,
        {"query": "ANSSI-CC-PP-2018/03", "search_type": "name", "status": "archived"},
        {"expect_ids": set()},
    ),
    (
        "eucc-id",
        EUCCSearch,
        {"cert_id": "EUCC-3087-2025-0000000001-00000"},
        {"expect_ids": {"e2a88386bd8e37a6"}, "broadened": False},
    ),
    (
        "eucc-id-status-excludes",
        EUCCSearch,
        {"cert_id": "EUCC-3087-2025-0000000001-00000", "status": "archived"},
        {"expect_ids": set()},
    ),
    (
        "eucc-name",
        EUCCSearch,
        {"query": "Secure Smart Grid Hub (SGH-S)", "search_type": "name"},
        {"expect_ids": {"5c5769d9a7c92821"}},
    ),
    (
        "eucc-name-prefix-broadens",
        EUCCSearch,
        {"query": "gri", "search_type": "name"},
        {"expect_ids": {"5c5769d9a7c92821"}, "broadened": True},
    ),
    (
        "cve-id",
        CVESearch,
        {"query": "CVE-2019-15809"},
        {"expect_ids": {"CVE-2019-15809"}, "id_field": "cve_id", "broadened": False},
    ),
    ("cve-severity-medium", CVESearch, {"severities": SEVERITY_MEDIUM}, {"expect_count": 2}),
    ("cve-severity-critical-none", CVESearch, {"severities": SEVERITY_CRITICAL}, {"expect_count": 0}),
    ("cve-score-in-range", CVESearch, {"score_from": "4", "score_to": "5"}, {"expect_count": 2}),
    ("cve-score-above-none", CVESearch, {"score_from": "8"}, {"expect_count": 0}),
    ("cpe-query", CPESearch, {"query": "tecsec"}, {"expect_count": 1}),
    ("cpe-vendor", CPESearch, {"vendor": "tecsec"}, {"expect_count": 1}),
]


@pytest.mark.parametrize("name,search_cls,params,expect", CASES, ids=[c[0] for c in CASES])
def test_search_case(name, search_cls, params, expect, check):
    check(search_cls, params, **expect)
