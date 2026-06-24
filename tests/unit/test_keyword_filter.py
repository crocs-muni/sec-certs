"""Unit tests for the extracted-keywords tree filter (no DB required)."""

from sec_certs_page.common.keyword_groups import build_keyword_tree, keyword_units
from sec_certs_page.common.search.fields import ListField
from sec_certs_page.common.search.query import build_keyword_query
from sec_certs_page.common.tasks.index import keyword_paths
from tantivy import Document, Index, SchemaBuilder

# --- keyword_paths -----------------------------------------------------------


def test_keyword_paths_expands_ancestors():
    kw = {"hash_function": {"SHA": {"SHA2": {"SHA-256": 1, "SHA-512": 1}}}}
    assert keyword_paths(kw) == ["hash_function", "hash_function.SHA", "hash_function.SHA.SHA2"]


def test_keyword_paths_two_level_category():
    kw = {"vendor": {"Samsung": {"Samsung": 11}}, "cc_sar": {"ADV": {"ADV_ARC": 1}}}
    assert set(keyword_paths(kw)) == {"vendor", "vendor.Samsung", "cc_sar", "cc_sar.ADV"}


def test_keyword_paths_skips_empty():
    # Pruned/empty category dicts produce no matches.
    assert keyword_paths({"fips_cert_id": {}}) == []
    assert keyword_paths(None) == []
    assert keyword_paths({}) == []


# --- ListField ---------------------------------------------------------------


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


# --- build_keyword_tree ------------------------------------------------------


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


# --- build_keyword_query (real tantivy index) --------------------------------


def _kw_index():
    schema = (
        SchemaBuilder()
        .add_text_field("dgst", stored=True, tokenizer_name="raw", index_option="basic")
        .add_text_field("keywords_cert", stored=False, tokenizer_name="raw", index_option="basic")
        .add_text_field("keywords_report", stored=False, tokenizer_name="raw", index_option="basic")
        .add_text_field("keywords_target", stored=False, tokenizer_name="raw", index_option="basic")
        .build()
    )
    index = Index(schema)
    writer = index.writer()

    def add(dgst, cert=None, report=None, target=None):
        doc = Document()
        doc.add_text("dgst", dgst)
        for field, kws in (("keywords_cert", cert), ("keywords_report", report), ("keywords_target", target)):
            for path in kws or []:
                doc.add_text(field, path)
        writer.add_document(doc)

    # A: SHA2 in cert. B: AES in report. C: both SHA2 (target) and AES (cert).
    add("A", cert=["hash_function", "hash_function.SHA", "hash_function.SHA.SHA2"])
    add("B", report=["symmetric_crypto", "symmetric_crypto.AES_competition", "symmetric_crypto.AES_competition.AES"])
    add(
        "C",
        target=["hash_function", "hash_function.SHA", "hash_function.SHA.SHA2"],
        cert=["symmetric_crypto", "symmetric_crypto.AES_competition", "symmetric_crypto.AES_competition.AES"],
    )
    writer.commit()
    index.reload()
    return index, schema


def _hits(index, schema, query):
    searcher = index.searcher()
    result = searcher.search(query, limit=10)
    return {searcher.doc(addr)["dgst"][0] for _, addr in result.hits}


def test_build_keyword_query_or_matches_any():
    index, schema = _kw_index()
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    q = build_keyword_query(
        schema, [["hash_function.SHA.SHA2"], ["symmetric_crypto.AES_competition.AES"]], fields, "or"
    )
    assert _hits(index, schema, q) == {"A", "B", "C"}


def test_build_keyword_query_and_requires_all_units():
    index, schema = _kw_index()
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    # Two separate units -> the cert must satisfy BOTH. Only C has both keywords.
    q = build_keyword_query(
        schema, [["hash_function.SHA.SHA2"], ["symmetric_crypto.AES_competition.AES"]], fields, "and"
    )
    assert _hits(index, schema, q) == {"C"}


def test_build_keyword_query_and_ors_within_a_unit():
    index, schema = _kw_index()
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    # One unit with two paths (e.g. a whole group) -> ANY of them satisfies it, even in "and".
    q = build_keyword_query(schema, [["hash_function.SHA.SHA2", "symmetric_crypto.AES_competition.AES"]], fields, "and")
    assert _hits(index, schema, q) == {"A", "B", "C"}


def test_build_keyword_query_internal_node_matches_descendants():
    index, schema = _kw_index()
    fields = ["keywords_cert", "keywords_report", "keywords_target"]
    q = build_keyword_query(schema, [["hash_function"]], fields, "or")
    assert _hits(index, schema, q) == {"A", "C"}


def test_build_keyword_query_doc_source_restriction():
    index, schema = _kw_index()
    # AES only counts in 'report' (B) or 'cert' (C); restricting to report finds only B.
    q = build_keyword_query(schema, [["symmetric_crypto.AES_competition.AES"]], ["keywords_report"], "or")
    assert _hits(index, schema, q) == {"B"}


# --- keyword_units (group token expansion) -----------------------------------


def test_keyword_units_expands_group_tokens():
    units = keyword_units(["cryptography", "hash_function.SHA"], "cc")
    # The bare path stays a single-path unit.
    assert ["hash_function.SHA"] in units
    # The group token expands to its category paths (a multi-path OR-unit).
    crypto_unit = next(u for u in units if len(u) > 1)
    assert "symmetric_crypto" in crypto_unit
    assert "hash_function" in crypto_unit


def test_keyword_units_empty():
    assert keyword_units(None, "cc") == []
    assert keyword_units([], "cc") == []
