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
    get_body_query,
    get_date_query,
    get_id_query,
    get_keyword_query,
    get_term_query,
    get_term_set_query,
    get_text_field_query,
    select_by_bitmask,
    select_by_list,
)
from ..eucc import eucc_eals, eucc_schemes
from .index import eucc_index, eucc_schema


class EUCCSearch(Search):
    search_args = {
        "cert_id": TextField(),
        "name": TextField(),
        "body": TextField(),
        "status": OptionField({"active", "archived"}),
        "sort_by": OptionField({"name", "not_valid_after", "not_valid_before", "cert_id", "scheme", "status", "eal"}),
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
    schema = eucc_schema
    index = eucc_index
    collection = mongo.db.eucc
    sorted_schemes = sorted(eucc_schemes)
    sorted_eals = sorted(eucc_eals)

    config = SearchConfig(
        default_sort_by="not_valid_before",
        query_targets={"fulltext": "body", "name": "name"},
        facets=(
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
                    eucc_index,
                    eucc_schema,
                    args["name"],
                    "name",
                    broader,
                    errors,
                    error_key=None if fulltext else "query",
                ),
            ),
            (
                Occur.Must,
                get_id_query(eucc_index, eucc_schema, args["cert_id"], broader, errors, "cert_id", "cert_id_tokenized"),
            ),
        ]
        if fulltext:
            text.append((Occur.Must, get_body_query(eucc_index, args["body"], ["target", "cert", "report"], errors)))

        kw_fields = [cls.kw_source_fields[s] for s in args["selected_kw_sources"]]
        query = build_must_query(
            Query.boolean_query(text),
            get_term_query(eucc_schema, "status", args["status"]),
            get_term_set_query(eucc_schema, "scheme", args["selected_schemes"], eucc_schemes),
            get_date_query(args["cert_date_from"], args["cert_date_to"], "not_valid_before", eucc_schema),
            get_date_query(args["archive_date_from"], args["archive_date_to"], "not_valid_after", eucc_schema),
            get_term_set_query(eucc_schema, "eal", args["selected_eals"], eucc_eals),
            get_keyword_query(eucc_schema, keyword_units(args["keywords"], "eucc"), kw_fields, args["kw_mode"]),
        )
        return query, errors
