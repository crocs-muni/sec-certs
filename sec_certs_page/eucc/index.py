from functools import cache

from tantivy import Index, SchemaBuilder

from ..common.search.index import get_index

eucc_schema = (
    SchemaBuilder()
    # internal purpouse fields
    .add_text_field("dgst", stored=True, tokenizer_name="raw", index_option="basic")
    # option fields
    .add_text_field("scheme", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("eal", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("status", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    # date fields
    .add_date_field("not_valid_before", stored=True, indexed=True, fast=True)
    .add_date_field("not_valid_after", stored=True, indexed=True, fast=True)
    # keywords
    .add_text_field("keywords_cert", stored=False, tokenizer_name="raw", index_option="basic")
    .add_text_field("keywords_report", stored=False, tokenizer_name="raw", index_option="basic")
    .add_text_field("keywords_target", stored=False, tokenizer_name="raw", index_option="basic")
    # full-text fields
    .add_text_field("name", stored=True, fast=True)
    .add_text_field("cert_id", stored=True, fast=True, tokenizer_name="raw")
    .add_text_field("cert_id_tokenized", stored=False)
    .add_text_field("body_cert", stored=True)
    .add_text_field("body_report", stored=True)
    .add_text_field("body_target", stored=True)
    .build()
)


@cache
def eucc_index() -> Index:
    return get_index(eucc_schema, "eucc")
