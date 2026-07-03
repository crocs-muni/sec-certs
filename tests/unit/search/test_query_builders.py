from datetime import datetime

import pytest
from sec_certs_page.cc.index import cc_schema
from sec_certs_page.common.search.query import (
    Errors,
    get_body_query,
    get_date_query,
    get_id_query,
    get_number_range_query,
    get_selection_query,
    get_term_query,
    get_term_set_query,
    get_text_field_query,
)
from sec_certs_page.vuln.index import cve_schema


@pytest.fixture
def cc_id_index(make_index):
    return make_index(
        cc_schema,
        [
            {"dgst": "A", "cert_id": "BSI-DSZ-CC-1091-2018", "cert_id_tokenized": "BSI-DSZ-CC-1091-2018"},
            {"dgst": "B", "cert_id": "ANSSI-CC-2019-42", "cert_id_tokenized": "ANSSI-CC-2019-42"},
        ],
    )


@pytest.fixture
def cc_name_index(make_index):
    return make_index(
        cc_schema,
        [
            {"dgst": "A", "name": "hardcoded secret module"},
            {"dgst": "B", "name": "unrelated product"},
        ],
    )


@pytest.fixture
def cc_body_index(make_index):
    return make_index(
        cc_schema,
        [
            {"dgst": "A", "body_target": "the key was hardcoded in the binary"},
            {"dgst": "B", "body_report": "no findings of note"},
        ],
    )


def test_id_query_exact_raw_match(cc_id_index, hits):
    errors = Errors()
    q = get_id_query(
        lambda: cc_id_index, cc_schema, "BSI-DSZ-CC-1091-2018", False, errors, "cert_id", "cert_id_tokenized"
    )
    assert hits(cc_id_index, q) == {"A"}
    assert not errors


def test_id_query_falls_back_to_tokenized(cc_id_index, hits):
    q = get_id_query(
        lambda: cc_id_index, cc_schema, "bsi-dsz-cc-1091-2018", False, Errors(), "cert_id", "cert_id_tokenized"
    )
    assert hits(cc_id_index, q) == {"A"}
    q = get_id_query(lambda: cc_id_index, cc_schema, "1091", False, Errors(), "cert_id", "cert_id_tokenized")
    assert hits(cc_id_index, q) == {"A"}


def test_id_query_no_match(cc_id_index, hits):
    q = get_id_query(
        lambda: cc_id_index, cc_schema, "NONEXISTENT-9999", False, Errors(), "cert_id", "cert_id_tokenized"
    )
    assert hits(cc_id_index, q) == set()


def test_text_field_query_exact_term(cc_name_index, hits):
    q = get_text_field_query(lambda: cc_name_index, cc_schema, "hardcoded", "name", False, Errors())
    assert hits(cc_name_index, q) == {"A"}


def test_text_field_query_broaden_enables_prefix(cc_name_index, hits):
    narrow = get_text_field_query(lambda: cc_name_index, cc_schema, "hardco", "name", False, Errors())
    assert hits(cc_name_index, narrow) == set()
    broad = get_text_field_query(lambda: cc_name_index, cc_schema, "hardco", "name", True, Errors())
    assert hits(cc_name_index, broad) == {"A"}


def test_term_set_query_returns_none_when_all_selected():
    assert get_term_set_query(cc_schema, "eal", ["EAL1", "EAL2"], ["EAL1", "EAL2"]) is None
    assert get_term_set_query(cc_schema, "eal", ["EAL1"], ["EAL1", "EAL2"]) is not None


def test_term_set_query_filters_to_selected(make_index, hits):
    index = make_index(
        cc_schema,
        [
            {"dgst": "A", "eal": "EAL1"},
            {"dgst": "B", "eal": "EAL2"},
            {"dgst": "C", "eal": "EAL3"},
        ],
    )
    q = get_term_set_query(cc_schema, "eal", ["EAL1", "EAL3"], ["EAL1", "EAL2", "EAL3"])
    assert hits(index, q) == {"A", "C"}


def test_term_query_none_for_empty_value():
    assert get_term_query(cc_schema, "status", None) is None
    assert get_term_query(cc_schema, "status", "") is None


def test_term_query_matches_exact(make_index, hits):
    index = make_index(
        cc_schema,
        [{"dgst": "A", "status": "active"}, {"dgst": "B", "status": "archived"}],
    )
    assert hits(index, get_term_query(cc_schema, "status", "active")) == {"A"}


def test_date_query_filters_by_range(make_index, hits):
    index = make_index(
        cc_schema,
        [
            {"dgst": "old", "not_valid_before": datetime(2018, 1, 1)},
            {"dgst": "mid", "not_valid_before": datetime(2020, 1, 1)},
            {"dgst": "new", "not_valid_before": datetime(2022, 1, 1)},
        ],
    )
    q = get_date_query(datetime(2019, 1, 1), datetime(2021, 1, 1), "not_valid_before", cc_schema)
    assert hits(index, q) == {"mid"}


def test_number_range_query_filters_by_score(make_index, hits):
    index = make_index(
        cve_schema,
        [
            {"cve_id": "low", "base_score": 2.0},
            {"cve_id": "med", "base_score": 5.0},
            {"cve_id": "high", "base_score": 9.0},
        ],
    )
    q = get_number_range_query(4.0, 6.0, "base_score", cve_schema)
    assert hits(index, q, id_field="cve_id") == {"med"}
    q = get_number_range_query(8.0, None, "base_score", cve_schema)
    assert hits(index, q, id_field="cve_id") == {"high"}


def test_body_query_matches_across_doc_types(cc_body_index, hits):
    q = get_body_query(lambda: cc_body_index, "hardcoded", ["target", "cert", "report"], Errors())
    assert hits(cc_body_index, q) == {"A"}


def test_body_query_respects_doc_type_restriction(cc_body_index, hits):
    q = get_body_query(lambda: cc_body_index, "hardcoded", ["cert", "report"], Errors())
    assert hits(cc_body_index, q) == set()


def test_body_query_none_value_matches_nothing(cc_body_index, hits):
    q = get_body_query(lambda: cc_body_index, None, ["target", "cert", "report"], Errors())
    assert hits(cc_body_index, q) == set()


def test_selection_query_uses_selected_ids(make_index, hits):
    index = make_index(
        cc_schema,
        [
            {"dgst": "A", "category": "ICs"},
            {"dgst": "B", "category": "Network"},
            {"dgst": "C", "category": "Databases"},
        ],
    )
    selection = {
        "ICs": {"id": "ICs", "selected": True},
        "Network": {"id": "Network", "selected": False},
        "Databases": {"id": "Databases", "selected": True},
    }
    q = get_selection_query(cc_schema, "category", selection)
    assert hits(index, q) == {"A", "C"}
