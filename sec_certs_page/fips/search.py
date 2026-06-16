from typing import Any
from .. import mongo
from ..common.search.query import Search, select_by_id, select_by_bitmask, detect_advanced_syntax, get_text_query, get_date_query
from .index import fips_schema, fips_index
from ..fips import fips_types as fips_categories, fips_levels
from ..common.search.fields import TextField, OptionField, DateField, IntField
from tantivy import Query, Occur

class FIPSSearch(Search):
    search_args = {
        "cert_id": TextField(),
        "vendor": TextField(),
        "name": TextField(),
        "body": TextField(),
        "cat": TextField(),
        "status": OptionField({"active", "historical", "revoked"}),
        "sort_by": OptionField({"name", "validation_date", "validation_date", "sunset_date", "cert_id", "vendor", "status", "level"}),
        "sort_dir": OptionField({"desc", "asc"}),
        "level": IntField(base=16),
        "validation_date_from": DateField(),
        "validation_date_to": DateField(),
        "sunset_date_from": DateField(),
        "sunset_date_to": DateField()
    }
    snippet_fields = {"policy": "body"}
    schema = fips_schema
    index = fips_index
    collection = mongo.db.fips

    @classmethod
    def _enrich_args(cls, parsed: dict) -> dict:
        fulltext = parsed["search_type"] == "fulltext"
        advanced = any(parsed[a] is not None for a in cls.search_args if a not in ["sort_by", "sort_dir"])

        if not advanced and not parsed["query"]:
            parsed["sort_by"] = parsed["sort_by"] or "cert_id"
            parsed["sort_dir"] = parsed["sort_dir"] or "desc"

        if fulltext:
            parsed["body"] = parsed["query"]
        else:
            parsed["name"] = parsed["query"]

        return {
            "advanced": advanced,
            "selected_categories": select_by_id(parsed["cat"], fips_categories),
            "selected_levels": select_by_bitmask(parsed["level"], fips_levels),
            **parsed
        }

    @classmethod
    def _get_body_query(cls, query: str, errors: dict) -> Query:
        if query is None:
            return Query.empty_query()

        body_subquery = []
        advanced_features = detect_advanced_syntax(query)
        if "field_prefix" not in advanced_features:
            query = f"body:{query}"

        parsed_query, err = fips_index().parse_query_lenient(query, default_field_names=["body"], conjunction_by_default=True, allow_regexes=False)
        if err:
            errors.update({"query": [str(e) for e in err]})

        body_subquery.append((Occur.Should, parsed_query))

        return Query.boolean_query(body_subquery)

    @classmethod
    def _build_cert_id_query(cls, query: str | None, errors: dict) -> Query:
        if query is None:
            return Query.all_query()

        if "field_prefix" not in detect_advanced_syntax(query):
            query = f"cert_id:{query}"

        parsed_query, err = fips_index().parse_query_lenient(query, default_field_names=["cert_id"], conjunction_by_default=True, allow_regexes=False)
        if err:
            errors.update({"cert_id": [str(e) for e in err]})

        return parsed_query

    @classmethod
    def _build_text_fields_query(cls, args: dict, broader: bool, errors: dict, fulltext: bool) -> Query:
        subqueries = []
        for field in ["name", "vendor"]:
            query, err = get_text_query(args[field], field, broader, fips_index(), fips_schema)
            if err:
                if not fulltext and field == "name":
                    field = "query"

                errors.update({field: [str(e) for e in err]})

            subqueries.append((Occur.Must, query))

        subqueries.append((Occur.Must, cls._build_cert_id_query(args["cert_id"], errors)))

        if fulltext:
            subqueries.append((Occur.Must, cls._get_body_query(args["body"], errors)))

        return Query.boolean_query(subqueries)


    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Any]:
        subqueries = []
        errors = {}

        subqueries.append((Occur.Must, cls._build_text_fields_query(args, broader, errors, fulltext)))

        if args["status"]:
            subqueries.append((Occur.Must, Query.term_query(fips_schema, "status", args["status"])))

        subqueries.append((Occur.Must, get_date_query(args["validation_date_from"], args["validation_date_to"], "validation_date", fips_schema)))
        subqueries.append((Occur.Must, get_date_query(args["sunset_date_from"], args["sunset_date_to"], "sunset_date", fips_schema)))

        categories = [key for key, val in args["selected_categories"].items() if val["selected"]]
        subqueries.append((Occur.Must, Query.term_set_query(fips_schema, "category", categories)))

        if len(args["selected_levels"]) < len(fips_levels):
            subqueries.append((Occur.Must, Query.term_set_query(fips_schema, "level", args["selected_levels"])))

        return Query.boolean_query(subqueries), errors