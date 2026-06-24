from tantivy import Occur, Query

from .. import mongo
from ..cc import cc_categories, cc_schemes
from ..common.keyword_groups import keyword_units
from ..common.search.fields import DateField, IntField, ListField, OptionField, TextField
from ..common.search.query import (
    Errors,
    Facet,
    Search,
    SearchConfig,
    build_must_query,
    get_body_query,
    get_date_query,
    get_keyword_query,
    get_selection_query,
    get_term_query,
    get_term_set_query,
    get_text_field_query,
    select_by_bitmask,
    select_by_id,
    select_by_list,
)
from .index import pp_index, pp_schema


class PPSearch(Search):
    search_args = {
        "name": TextField(),
        "body": TextField(),
        "cat": TextField(),
        "status": OptionField({"active", "archived"}),
        "sort_by": OptionField({"name", "not_valid_before", "not_valid_after", "scheme", "status"}),
        "sort_dir": OptionField({"desc", "asc"}),
        "schemes": IntField(base=16),
        "cert_date_from": DateField(),
        "cert_date_to": DateField(),
        "archive_date_from": DateField(),
        "archive_date_to": DateField(),
        "keywords": ListField(),
        "kw_sources": ListField(),
        "kw_mode": OptionField({"and", "or"}),
    }
    snippet_fields = {"report": "body_report", "profile": "body_profile"}
    kw_source_fields = {"report": "keywords_report", "profile": "keywords_profile"}
    schema = pp_schema
    index = pp_index
    collection = mongo.db.pp
    sorted_schemes = sorted(cc_schemes)

    config = SearchConfig(
        default_sort_by="not_valid_before",
        query_targets={"fulltext": "body", "name": "name"},
        facets=(
            Facet("selected_categories", select_by_id, "cat", cc_categories),
            Facet("selected_schemes", select_by_bitmask, "schemes", sorted_schemes),
            Facet("selected_kw_sources", select_by_list, "kw_sources", kw_source_fields),
        ),
    )

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Errors]:
        errors = Errors()

        text = [
            (
                Occur.Must,
                get_text_field_query(
                    pp_index, pp_schema, args["name"], "name", broader, errors, error_key=None if fulltext else "query"
                ),
            ),
        ]
        if fulltext:
            text.append((Occur.Must, get_body_query(pp_index, args["body"], ["report", "profile"], errors)))

        kw_fields = [cls.kw_source_fields[s] for s in args["selected_kw_sources"]]
        query = build_must_query(
            Query.boolean_query(text),
            get_term_query(pp_schema, "status", args["status"]),
            get_term_set_query(pp_schema, "scheme", args["selected_schemes"], cc_schemes),
            get_date_query(args["cert_date_from"], args["cert_date_to"], "not_valid_before", pp_schema),
            get_date_query(args["archive_date_from"], args["archive_date_to"], "not_valid_after", pp_schema),
            get_selection_query(pp_schema, "category", args["selected_categories"]),
            get_keyword_query(pp_schema, keyword_units(args["keywords"], "pp"), kw_fields, args["kw_mode"]),
        )
        return query, errors
