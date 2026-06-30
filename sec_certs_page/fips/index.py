from functools import cache

from tantivy import Index, SchemaBuilder

from ..common.search.index import get_index

fips_schema = (
    SchemaBuilder()
    # internal purpouse fields
    .add_text_field("dgst", stored=True, tokenizer_name="raw", index_option="basic")
    # option fields
    .add_text_field("category", stored=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("status", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    .add_text_field("level", stored=True, fast=True, tokenizer_name="raw", index_option="basic")
    # date fields
    .add_date_field("validation_date", stored=True, indexed=True, fast=True)
    .add_date_field("sunset_date", stored=True, indexed=True, fast=True)
    # full-text fields
    .add_text_field("name", stored=True, fast=True)
    .add_integer_field("cert_id", stored=True, indexed=True, fast=True)
    .add_text_field("vendor", stored=True, fast=True)
    # extracted-keyword path field (multi-valued); FIPS has a single document source
    .add_text_field("keywords_target", stored=False, tokenizer_name="raw", index_option="basic")
    .add_text_field("body", stored=True)
    .build()
)


@cache
def fips_index() -> Index:
    return get_index(fips_schema, "fips")
