from tantivy import Occur, Query

from .. import mongo
from ..cc import cc_categories, cc_eals, cc_schemes
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
    get_id_query,
    get_keyword_query,
    get_selection_query,
    get_term_query,
    get_term_set_query,
    get_text_field_query,
    select_by_bitmask,
    select_by_id,
    select_by_list,
)
from .index import cc_index, cc_schema


class CCSearch(Search):
    search_args = {
        "cert_id": TextField(),
        "manufacturer": TextField(),
        "name": TextField(),
        "body": TextField(),
        "cert_lab": TextField(),
        "cat": TextField(),
        "status": OptionField({"active", "archived"}),
        "sort_by": OptionField(
            {
                "name",
                "not_valid_after",
                "not_valid_before",
                "cert_id",
                "manufacturer",
                "cert_lab",
                "scheme",
                "status",
                "eal",
            }
        ),
        "sort_dir": OptionField({"desc", "asc"}),
        "schemes": IntField(base=16),
        "eal": IntField(base=16),
        "cert_date_from": DateField(),
        "cert_date_to": DateField(),
        "archive_date_from": DateField(),
        "archive_date_to": DateField(),
        "keywords": ListField(),
        "kw_sources": ListField(),
        "kw_mode": OptionField({"and", "or"}),
    }
    snippet_fields = {"cert": "body_cert", "report": "body_report", "target": "body_target"}
    kw_source_fields = {"cert": "keywords_cert", "report": "keywords_report", "target": "keywords_target"}
    schema = cc_schema
    index = cc_index
    collection = mongo.db.cc
    sorted_schemes = sorted(cc_schemes)
    sorted_eals = sorted(cc_eals)

    config = SearchConfig(
        default_sort_by="not_valid_before",
        query_targets={"fulltext": "body", "name": "name"},
        facets=(
            Facet("selected_categories", select_by_id, "cat", cc_categories),
            Facet("selected_schemes", select_by_bitmask, "schemes", sorted_schemes),
            Facet("selected_eals", select_by_bitmask, "eal", sorted_eals),
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
                    cc_index, cc_schema, args["name"], "name", broader, errors, error_key=None if fulltext else "query"
                ),
            ),
            (
                Occur.Must,
                get_text_field_query(cc_index, cc_schema, args["manufacturer"], "manufacturer", broader, errors),
            ),
            (Occur.Must, get_text_field_query(cc_index, cc_schema, args["cert_lab"], "cert_lab", broader, errors)),
            (
                Occur.Must,
                get_id_query(cc_index, cc_schema, args["cert_id"], broader, errors, "cert_id", "cert_id_tokenized"),
            ),
        ]
        if fulltext:
            text.append((Occur.Must, get_body_query(cc_index, args["body"], ["target", "cert", "report"], errors)))

        kw_fields = [cls.kw_source_fields[s] for s in args["selected_kw_sources"]]
        query = build_must_query(
            Query.boolean_query(text),
            get_term_query(cc_schema, "status", args["status"]),
            get_term_set_query(cc_schema, "scheme", args["selected_schemes"], cc_schemes),
            get_date_query(args["cert_date_from"], args["cert_date_to"], "not_valid_before", cc_schema),
            get_date_query(args["archive_date_from"], args["archive_date_to"], "not_valid_after", cc_schema),
            get_selection_query(cc_schema, "category", args["selected_categories"]),
            get_term_set_query(cc_schema, "eal", args["selected_eals"], cc_eals),
            get_keyword_query(cc_schema, keyword_units(args["keywords"], "cc"), kw_fields, args["kw_mode"]),
        )
        return query, errors
