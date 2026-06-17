from typing import Any

from tantivy import Occur, Query

from .. import mongo
from ..common.search.fields import DateField, IntField, OptionField, TextField
from ..common.search.query import Search, detect_advanced_syntax, get_date_query, get_text_query, select_by_bitmask
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
    }
    snippet_fields = {"cert": "body_cert", "report": "body_report", "target": "body_target"}
    schema = eucc_schema
    index = eucc_index
    collection = mongo.db.eucc
    sorted_schemes = sorted(eucc_schemes)
    sorted_eals = sorted(eucc_eals)

    @classmethod
    def _enrich_args(cls, parsed: dict) -> dict:
        fulltext = parsed["search_type"] == "fulltext"
        advanced = any(parsed[a] is not None for a in cls.search_args if a not in ["sort_by", "sort_dir"])

        if not advanced and not parsed["query"]:
            parsed["sort_by"] = parsed["sort_by"] or "not_valid_before"
            parsed["sort_dir"] = parsed["sort_dir"] or "desc"

        if fulltext:
            parsed["body"] = parsed["query"]
        else:
            parsed["name"] = parsed["query"]

        return {
            "advanced": advanced,
            "selected_schemes": select_by_bitmask(parsed["schemes"], cls.sorted_schemes),
            "selected_eals": select_by_bitmask(parsed["eal"], cls.sorted_eals),
            **parsed,
        }

    @classmethod
    def _get_body_query(cls, query: str, errors: dict) -> Query:
        if query is None:
            return Query.empty_query()

        body_subquery = []
        advanced_features = detect_advanced_syntax(query)
        for doc_type in ["target", "cert", "report"]:
            body = query
            if "field_prefix" not in advanced_features:
                body = f"body_{doc_type}:{query}"

            parsed_query, err = eucc_index().parse_query_lenient(
                body, default_field_names=[f"body_{doc_type}"], conjunction_by_default=True, allow_regexes=False
            )
            if err:
                errors.update({"query": [str(e) for e in err]})

            body_subquery.append((Occur.Should, parsed_query))

        return Query.boolean_query(body_subquery)

    @classmethod
    def _build_text_fields_query(cls, args: dict, broader: bool, errors: dict, fulltext: bool) -> Query:
        subqueries = []
        query, err = get_text_query(args["name"], "name", broader, eucc_index(), eucc_schema)
        if err:
            field = "name" if fulltext else "query"
            errors.update({field: [str(e) for e in err]})
        subqueries.append((Occur.Must, query))

        cert_id_queries = []
        for field in ["cert_id_raw", "cert_id"]:
            query, err = get_text_query(args["cert_id"], field, broader, eucc_index(), eucc_schema)
            if err:
                errors.update({"cert_id": [str(e) for e in err]})

            cert_id_queries.append((Occur.Should, query))

        subqueries.append((Occur.Must, Query.boolean_query(cert_id_queries)))

        if fulltext:
            subqueries.append((Occur.Must, cls._get_body_query(args["body"], errors)))

        return Query.boolean_query(subqueries)

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Any]:
        subqueries = []
        errors = {}

        subqueries.append((Occur.Must, cls._build_text_fields_query(args, broader, errors, fulltext)))

        if args["status"]:
            subqueries.append((Occur.Must, Query.term_query(eucc_schema, "status", args["status"])))

        subqueries.append((Occur.Must, Query.term_set_query(eucc_schema, "scheme", args["selected_schemes"])))

        subqueries.append(
            (Occur.Must, get_date_query(args["cert_date_from"], args["cert_date_to"], "not_valid_before", eucc_schema))
        )
        subqueries.append(
            (
                Occur.Must,
                get_date_query(args["archive_date_from"], args["archive_date_to"], "not_valid_after", eucc_schema),
            )
        )

        if len(args["selected_eals"]) < len(eucc_eals):
            subqueries.append((Occur.Must, Query.term_set_query(eucc_schema, "eal", args["selected_eals"])))

        return Query.boolean_query(subqueries), errors
