from functools import cache

from tantivy import Index, SchemaBuilder

from ..common.search.index import get_index

cve_schema = (
    SchemaBuilder()
    .add_text_field("id", stored=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("cve_id", stored=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("cve_id_tokenized", stored=False)
    .add_integer_field("cve_number", stored=False, indexed=True, fast=True)
    .add_text_field("severity", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("cwe", stored=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("cwe_tokenized", stored=False)
    .add_float_field("base_score", stored=True, indexed=True, fast=True)
    .add_date_field("published_date", stored=True, indexed=True, fast=True)
    .add_integer_field("cert_count", stored=True, indexed=True, fast=True)
    .build()
)

cpe_schema = (
    SchemaBuilder()
    .add_text_field("id", stored=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("uri", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("uri_tokenized", stored=False)
    .add_text_field("vendor", stored=True, fast=True)
    .add_text_field("product", stored=True, fast=True)
    .add_text_field("cpe_title", stored=True, fast=True)
    .add_text_field("version", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_integer_field("cert_count", stored=True, indexed=True, fast=True)
    .build()
)


@cache
def cve_index() -> Index:
    return get_index(cve_schema, "cve")


@cache
def cpe_index() -> Index:
    return get_index(cpe_schema, "cpe")
