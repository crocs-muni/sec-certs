from tantivy import Occur, Query

from .. import mongo
from ..common.keyword_groups import keyword_units
from ..common.search.fields import DateField, IntField, ListField, OptionField, TextField
from ..common.search.query import (
    Errors,
    Facet,
    Search,
    SearchConfig,
    build_must_query,
    detect_advanced_syntax,
    get_body_query,
    get_date_query,
    get_keyword_query,
    get_selection_query,
    get_term_query,
    get_term_set_query,
    get_text_field_query,
    select_by_bitmask,
    select_by_id,
)
from ..fips import fips_levels
from ..fips import fips_types as fips_categories
from .index import fips_index, fips_schema


def _fips_cert_id_query(value: str | None, errors: Errors) -> Query:
    if value is None:
        return Query.all_query()

    text = value if "field_prefix" in detect_advanced_syntax(value) else f"cert_id:{value}"
    parsed_query, err = fips_index().parse_query_lenient(
        text, default_field_names=["cert_id"], conjunction_by_default=True, allow_regexes=False
    )
    errors.add("cert_id", err)
    return parsed_query


class FIPSSearch(Search):
    search_args = {
        "cert_id": TextField(),
        "vendor": TextField(),
        "name": TextField(),
        "body": TextField(),
        "cat": TextField(),
        "status": OptionField({"active", "historical", "revoked"}),
        "sort_by": OptionField(
            {"name", "validation_date", "validation_date", "sunset_date", "cert_id", "vendor", "status", "level"}
        ),
        "sort_dir": OptionField({"desc", "asc"}),
        "level": IntField(base=16),
        "validation_date_from": DateField(),
        "validation_date_to": DateField(),
        "sunset_date_from": DateField(),
        "sunset_date_to": DateField(),
        "keywords": ListField(),
        "kw_mode": OptionField({"and", "or"}),
    }
    snippet_fields = {"policy": "body"}
    kw_source_fields = {"target": "keywords_target"}
    schema = fips_schema
    index = fips_index
    collection = mongo.db.fips

    config = SearchConfig(
        default_sort_by="cert_id",
        query_targets={"fulltext": "body", "name": "name"},
        facets=(
            Facet("selected_categories", select_by_id, "cat", fips_categories),
            Facet("selected_levels", select_by_bitmask, "level", fips_levels),
        ),
    )

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Errors]:
        errors = Errors()

        text = [
            (
                Occur.Must,
                get_text_field_query(
                    fips_index,
                    fips_schema,
                    args["name"],
                    "name",
                    broader,
                    errors,
                    error_key=None if fulltext else "query",
                ),
            ),
            (Occur.Must, get_text_field_query(fips_index, fips_schema, args["vendor"], "vendor", broader, errors)),
            (Occur.Must, _fips_cert_id_query(args["cert_id"], errors)),
        ]
        if fulltext:
            text.append((Occur.Must, get_body_query(fips_index, args["body"], [None], errors)))

        query = build_must_query(
            Query.boolean_query(text),
            get_term_query(fips_schema, "status", args["status"]),
            get_date_query(args["validation_date_from"], args["validation_date_to"], "validation_date", fips_schema),
            get_date_query(args["sunset_date_from"], args["sunset_date_to"], "sunset_date", fips_schema),
            get_selection_query(fips_schema, "category", args["selected_categories"]),
            get_term_set_query(fips_schema, "level", args["selected_levels"], fips_levels),
            get_keyword_query(
                fips_schema, keyword_units(args["keywords"], "fips"), ["keywords_target"], args["kw_mode"]
            ),
        )
        return query, errors
