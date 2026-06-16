from typing import Any
from .. import mongo
from ..cc import cc_categories, cc_schemes
from ..common.search.query import Search, select_by_id, select_by_bitmask, detect_advanced_syntax, get_text_query, get_date_query
from .index import pp_schema, pp_index
from ..common.search.fields import TextField, OptionField, DateField, IntField
from tantivy import Query, Occur


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
        "archive_date_to": DateField()
    }
    snippet_fields = {"report": "body_report", "profile": "body_profile"}
    schema = pp_schema
    index = pp_index
    collection = mongo.db.pp
    sorted_schemes = sorted(cc_schemes)

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
            "selected_categories": select_by_id(parsed["cat"], cc_categories),
            "selected_schemes": select_by_bitmask(parsed["schemes"], cls.sorted_schemes),
            **parsed
        }

    @classmethod
    def _get_body_query(cls, query: str, errors: dict) -> Query:
        if query is None:
            return Query.empty_query()

        body_subquery = []
        advanced_features = detect_advanced_syntax(query)
        for doc_type in ["report", "profile"]:
            body = query
            if "field_prefix" not in advanced_features:
                body = f"body_{doc_type}:{query}"

            parsed_query, err = pp_index().parse_query_lenient(body, default_field_names=[f"body_{doc_type}"], conjunction_by_default=True, allow_regexes=False)
            if err:
                errors.update({"query": [str(e) for e in err]})

            body_subquery.append((Occur.Should, parsed_query))

        return Query.boolean_query(body_subquery)

    @classmethod
    def _build_text_fields_query(cls, args: dict, broader: bool, errors: dict, fulltext: bool) -> Query:
        subqueries = []
        for field in ["name"]:
            query, err = get_text_query(args[field], field, broader, pp_index(), pp_schema)
            if err:
                if not fulltext and field == "name":
                    field = "query"

                errors.update({field: [str(e) for e in err]})

            subqueries.append((Occur.Must, query))

        if fulltext:
            subqueries.append((Occur.Must, cls._get_body_query(args["body"], errors)))

        return Query.boolean_query(subqueries)

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Any]:
        subqueries = []
        errors = {}

        subqueries.append((Occur.Must, cls._build_text_fields_query(args, broader, errors, fulltext)))

        if args["status"]:
            subqueries.append((Occur.Must, Query.term_query(pp_schema, "status", args["status"])))

        subqueries.append((Occur.Must, Query.term_set_query(pp_schema, "scheme", args["selected_schemes"])))

        subqueries.append((Occur.Must, get_date_query(args["cert_date_from"], args["cert_date_to"], "not_valid_before", pp_schema)))
        subqueries.append((Occur.Must, get_date_query(args["archive_date_from"], args["archive_date_to"], "not_valid_after", pp_schema)))

        categories = [key for key, val in args["selected_categories"].items() if val["selected"]]
        subqueries.append((Occur.Must, Query.term_set_query(pp_schema, "category", categories)))

        return Query.boolean_query(subqueries), errors
