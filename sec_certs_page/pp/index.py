from functools import cache

from tantivy import Index, SchemaBuilder

from ..common.search.index import get_index

pp_schema = (
    SchemaBuilder()
    # internal purpouse fields
    .add_text_field("dgst", stored=True, tokenizer_name="raw", index_option="basic")
    # option fields
    .add_text_field("category", stored=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("status", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("scheme", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    # date fields
    .add_date_field("not_valid_before", stored=True, indexed=True, fast=True)
    .add_date_field("not_valid_after", stored=True, indexed=True, fast=True)
    # full-text fields
    .add_text_field("name", stored=True, fast=True)
    # extracted-keyword path fields (multi-valued), one per document source
    .add_text_field("keywords_report", stored=False, tokenizer_name="raw", index_option="basic")
    .add_text_field("keywords_profile", stored=False, tokenizer_name="raw", index_option="basic")
    .add_text_field("body_report", stored=True)
    .add_text_field("body_profile", stored=True)
    .build()
)


@cache
def pp_index() -> Index:
    return get_index(pp_schema, "pp")
