import re
from typing import Any

from tantivy import Occur, Query

from .. import mongo
from ..common.search.fields import DateField, FloatField, IntField, OptionField, TextField
from ..common.search.query import (
    Search,
    get_date_query,
    get_number_range_query,
    get_text_query,
    select_by_bitmask,
)
from .index import cpe_index, cpe_schema, cve_index, cve_schema

CVE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# A query that is itself a CPE URI (cpe:2.3:... or cpe:/...). Such a query must not go through
# the tantivy query parser, which would read the "cpe:" / inner colons as field prefixes.
CPE_URI_RE = re.compile(r"^cpe:", re.IGNORECASE)


class CVESearch(Search):
    search_args = {
        "severities": IntField(base=16),
        "score_from": FloatField(min=0, max=10),
        "score_to": FloatField(min=0, max=10),
        "date_from": DateField(),
        "date_to": DateField(),
        "cwe": TextField(),
        "sort_by": OptionField({"cve_number", "base_score", "published_date", "severity", "cert_count"}),
        "sort_dir": OptionField({"desc", "asc"}),
    }
    snippet_fields: dict[str, str] = {}
    schema = cve_schema
    index = cve_index
    collection = mongo.db.cve
    sorted_severities = CVE_SEVERITIES

    @classmethod
    def _enrich_args(cls, parsed: dict) -> dict:
        advanced = any(parsed[a] is not None for a in cls.search_args if a not in ["sort_by", "sort_dir"])

        if not parsed["query"]:
            parsed["sort_by"] = parsed["sort_by"] or "published_date"
            parsed["sort_dir"] = parsed["sort_dir"] or "desc"

        parsed["cve_id"] = parsed["query"]

        return {
            "advanced": advanced,
            "selected_severities": select_by_bitmask(parsed["severities"], cls.sorted_severities),
            **parsed,
        }

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Any]:
        subqueries = []
        errors: dict[str, list[str]] = {}

        if args["cve_id"]:
            # The raw "cve_id" field has no positions/tokenization, so it can only take an exact
            # term query; the tokenized "cve_tokenized" field powers partial/fuzzy matching.
            id_subqueries = [(Occur.Should, Query.term_query(cve_schema, "cve_id", args["cve_id"]))]
            query, err = get_text_query(args["cve_id"], "cve_tokenized", broader, cve_index(), cve_schema)
            if err:
                errors.update({"query": [str(e) for e in err]})
            id_subqueries.append((Occur.Should, query))
            subqueries.append((Occur.Must, Query.boolean_query(id_subqueries)))

        if len(args["selected_severities"]) < len(cls.sorted_severities):
            subqueries.append((Occur.Must, Query.term_set_query(cve_schema, "severity", args["selected_severities"])))

        subqueries.append(
            (Occur.Must, get_number_range_query(args["score_from"], args["score_to"], "base_score", cve_schema))
        )
        subqueries.append(
            (Occur.Must, get_date_query(args["date_from"], args["date_to"], "published_date", cve_schema))
        )

        if args["cwe"]:
            query, err = get_text_query(args["cwe"], "cwe", broader, cve_index(), cve_schema)
            if err:
                errors.update({"cwe": [str(e) for e in err]})
            subqueries.append((Occur.Must, query))

        return Query.boolean_query(subqueries), errors


class CPESearch(Search):
    search_args = {
        "vendor": TextField(),
        "product": TextField(),
        "cpe_title": TextField(),
        "version": TextField(),
        "sort_by": OptionField({"uri", "vendor", "product", "cpe_title", "version", "cert_count"}),
        "sort_dir": OptionField({"desc", "asc"}),
    }
    snippet_fields: dict[str, str] = {}
    schema = cpe_schema
    index = cpe_index
    collection = mongo.db.cpe

    @classmethod
    def _enrich_args(cls, parsed: dict) -> dict:
        advanced = any(parsed[a] is not None for a in cls.search_args if a not in ["sort_by", "sort_dir"])

        if not parsed["query"]:
            parsed["sort_by"] = parsed["sort_by"] or "cert_count"
            parsed["sort_dir"] = parsed["sort_dir"] or "desc"

        parsed["text"] = parsed["query"]

        return {
            "advanced": advanced,
            **parsed,
        }

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Any]:
        subqueries = []
        errors: dict[str, list[str]] = {}

        query_text = args["text"]
        if query_text and CPE_URI_RE.match(query_text):
            # A full CPE URI: match it exactly on the raw uri field, bypassing the query parser
            # (its "cpe:"/inner colons would otherwise be read as field prefixes).
            subqueries.append((Occur.Must, Query.term_query(cpe_schema, "uri", query_text)))
        elif query_text:
            text_q, err = get_text_query(query_text, "text", broader, cpe_index(), cpe_schema)
            if err:
                errors.update({"query": [str(e) for e in err]})
            # Tokenized/partial match (incl. uri tokens) OR an exact raw-uri match.
            subqueries.append(
                (
                    Occur.Must,
                    Query.boolean_query(
                        [
                            (Occur.Should, text_q),
                            (Occur.Should, Query.term_query(cpe_schema, "uri", query_text)),
                        ]
                    ),
                )
            )

        for field in ("vendor", "product", "cpe_title"):
            field_query, err = get_text_query(args[field], field, broader, cpe_index(), cpe_schema)
            if err:
                errors.update({field: [str(e) for e in err]})
            subqueries.append((Occur.Must, field_query))

        if args["version"]:
            subqueries.append((Occur.Must, Query.term_query(cpe_schema, "version", args["version"])))

        return Query.boolean_query(subqueries), errors
