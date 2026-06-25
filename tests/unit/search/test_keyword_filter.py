import pytest
from sec_certs_page.common.keyword_groups import build_keyword_tree, keyword_units
from sec_certs_page.common.search.fields import ListField
from sec_certs_page.common.search.query import build_keyword_query
from sec_certs_page.common.tasks.index import keyword_paths
from tantivy import SchemaBuilder


def test_keyword_paths_expands_ancestors():
    kw = {"hash_function": {"SHA": {"SHA2": {"SHA-256": 1, "SHA-512": 1}}}}
    assert keyword_paths(kw) == ["hash_function", "hash_function.SHA", "hash_function.SHA.SHA2"]


def test_keyword_paths_two_level_category():
    kw = {"vendor": {"Samsung": {"Samsung": 11}}, "cc_sar": {"ADV": {"ADV_ARC": 1}}}
    assert set(keyword_paths(kw)) == {"vendor", "vendor.Samsung", "cc_sar", "cc_sar.ADV"}


def test_keyword_paths_skips_empty():
    assert keyword_paths({"fips_cert_id": {}}) == []
    assert keyword_paths(None) == []
    assert keyword_paths({}) == []


def test_listfield_empty_is_none():
    assert ListField().parse(None).value is None
    assert ListField().parse("").value is None


def test_listfield_splits_on_separator():
    res = ListField().parse("hash_function.SHA,vendor.Samsung")
    assert res.ok
    assert res.value == ["hash_function.SHA", "vendor.Samsung"]


def test_listfield_rejects_too_many():
    res = ListField(max_items=2).parse("a,b,c")
    assert not res.ok


def test_build_keyword_tree_cc_structure():
    tree = build_keyword_tree("cc")
    groups = {g["name"]: g for g in tree}
    assert set(groups) == {"Cryptography", "Device", "Common Criteria", "Security", "Other"}
    hf = next(c for c in groups["Cryptography"]["children"] if c["path"] == "hash_function")
    sha = next(c for c in hf["children"] if c["name"] == "SHA")
    assert {c["name"] for c in sha["children"]} == {"SHA1", "SHA2", "SHA3"}
    assert next(c for c in sha["children"] if c["name"] == "SHA2")["path"] == "hash_function.SHA.SHA2"


def test_build_keyword_tree_fips_has_no_cc_group():
    groups = {g["name"] for g in build_keyword_tree("fips")}
    assert "Common Criteria" not in groups
    assert "Cryptography" in groups


@pytest.fixture
def kw_index(make_index):
    schema = (
        SchemaBuilder()
        .add_text_field("dgst", stored=True, tokenizer_name="raw", index_option="basic")
        .add_text_field("keywords_cert", stored=False, tokenizer_name="raw", index_option="basic")
        .add_text_field("keywords_report", stored=False, tokenizer_name="raw", index_option="basic")
        .add_text_field("keywords_target", stored=False, tokenizer_name="raw", index_option="basic")
        .build()
    )
    index = make_index(
        schema,
        [
            {"dgst": "A", "keywords_cert": ["hash_function", "hash_function.SHA", "hash_function.SHA.SHA2"]},
            {
                "dgst": "B",
                "keywords_report": [
                    "symmetric_crypto",
                    "symmetric_crypto.AES_competition",
                    "symmetric_crypto.AES_competition.AES",
                ],
            },
            {
                "dgst": "C",
                "keywords_target": ["hash_function", "hash_function.SHA", "hash_function.SHA.SHA2"],
                "keywords_cert": [
                    "symmetric_crypto",
                    "symmetric_crypto.AES_competition",
                    "symmetric_crypto.AES_competition.AES",
                ],
            },
        ],
    )
    return index, schema


def test_build_keyword_query_or_matches_any(kw_index, hits):
    index, schema = kw_index
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    q = build_keyword_query(
        schema, [["hash_function.SHA.SHA2"], ["symmetric_crypto.AES_competition.AES"]], fields, "or"
    )
    assert hits(index, q) == {"A", "B", "C"}


def test_build_keyword_query_and_requires_all_units(kw_index, hits):
    index, schema = kw_index
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    q = build_keyword_query(
        schema, [["hash_function.SHA.SHA2"], ["symmetric_crypto.AES_competition.AES"]], fields, "and"
    )
    assert hits(index, q) == {"C"}


def test_build_keyword_query_and_ors_within_a_unit(kw_index, hits):
    index, schema = kw_index
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    q = build_keyword_query(schema, [["hash_function.SHA.SHA2", "symmetric_crypto.AES_competition.AES"]], fields, "and")
    assert hits(index, q) == {"A", "B", "C"}


def test_build_keyword_query_internal_node_matches_descendants(kw_index, hits):
    index, schema = kw_index
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    q = build_keyword_query(schema, [["hash_function"]], fields, "or")
    assert hits(index, q) == {"A", "C"}


def test_build_keyword_query_doc_source_restriction(kw_index, hits):
    index, schema = kw_index
    q = build_keyword_query(schema, [["symmetric_crypto.AES_competition.AES"]], ["keywords_report"], "or")
    assert hits(index, q) == {"B"}


def test_keyword_units_expands_group_tokens():
    units = keyword_units(["cryptography", "hash_function.SHA"], "cc")
    assert ["hash_function.SHA"] in units
    crypto_unit = next(u for u in units if len(u) > 1)
    assert "symmetric_crypto" in crypto_unit
    assert "hash_function" in crypto_unit


def test_keyword_units_empty():
    assert keyword_units(None, "cc") == []
    assert keyword_units([], "cc") == []
