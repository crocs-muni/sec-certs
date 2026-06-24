import re

from tantivy import Query

from .. import mongo
from ..common.search.fields import DateField, FloatField, IntField, OptionField, TextField
from ..common.search.query import (
    Errors,
    Facet,
    Search,
    SearchConfig,
    build_must_query,
    get_date_query,
    get_id_query,
    get_number_range_query,
    get_term_query,
    get_term_set_query,
    get_text_field_query,
    select_by_bitmask,
)
from .index import cpe_index, cpe_schema, cve_index, cve_schema

CVE_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
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
    snippet_fields = {}
    schema = cve_schema
    index = cve_index
    collection = mongo.db.cve
    sorted_severities = CVE_SEVERITIES

    config = SearchConfig(
        default_sort_by="published_date",
        query_targets={"*": "cve_id"},
        facets=(Facet("selected_severities", select_by_bitmask, "severities", CVE_SEVERITIES),),
    )

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Errors]:
        errors = Errors()
        query = build_must_query(
            get_id_query(
                cve_index, cve_schema, args["cve_id"], broader, errors, "cve_id", "cve_id_tokenized", error_key="query"
            )
            if args["cve_id"]
            else None,
            get_term_set_query(cve_schema, "severity", args["selected_severities"], CVE_SEVERITIES),
            get_number_range_query(args["score_from"], args["score_to"], "base_score", cve_schema),
            get_date_query(args["date_from"], args["date_to"], "published_date", cve_schema),
            get_id_query(cve_index, cve_schema, args["cwe"], broader, errors, "cwe", "cwe_tokenized", error_key="cwe")
            if args["cwe"]
            else None,
        )
        return query, errors


class CPESearch(Search):
    search_args = {
        "uri": TextField(),
        "vendor": TextField(),
        "product": TextField(),
        "version": TextField(),
        "sort_by": OptionField({"uri", "vendor", "product", "cpe_title", "version", "cert_count"}),
        "sort_dir": OptionField({"desc", "asc"}),
    }
    snippet_fields = {}
    schema = cpe_schema
    index = cpe_index
    collection = mongo.db.cpe

    config = SearchConfig(
        default_sort_by="cert_count",
        query_targets={"*": "cpe_title"},
    )

    @classmethod
    def _build_query(cls, args: dict, broader: bool = False, fulltext: bool = False) -> tuple[Query, Errors]:
        errors = Errors()

        uri = args["uri"]
        if uri and CPE_URI_RE.match(uri):
            uri_query = Query.term_query(cpe_schema, "uri", uri)
        elif uri:
            uri_query = get_id_query(
                cpe_index, cpe_schema, uri, broader, errors, "uri", "uri_tokenized", error_key="uri"
            )
        else:
            uri_query = None

        query = build_must_query(
            get_text_field_query(
                cpe_index, cpe_schema, args["cpe_title"], "cpe_title", broader, errors, error_key="query"
            ),
            uri_query,
            get_text_field_query(cpe_index, cpe_schema, args["vendor"], "vendor", broader, errors),
            get_text_field_query(cpe_index, cpe_schema, args["product"], "product", broader, errors),
            get_term_query(cpe_schema, "version", args["version"]),
        )
        return query, errors
