import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any, ClassVar

from flask import current_app
from tantivy import (
    DocAddress,
    FieldType,
    Filter,
    Index,
    Occur,
    Order,
    Query,
    Schema,
    Searcher,
    SnippetGenerator,
    TextAnalyzerBuilder,
    Tokenizer,
)
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest

from ..views import Pagination
from .fields import FieldProtocol, IntField, OptionField, TextField

default_tokenizer = TextAnalyzerBuilder(Tokenizer.simple()).filter(Filter.lowercase()).build()


def select_by_id(selected: str, options: dict) -> dict:
    return {key: {**val, "selected": (val["id"] in selected) if selected else True} for key, val in options.items()}


def select_by_bitmask(mask: int | None, options: list) -> list:
    return [opt for i, opt in enumerate(options) if not mask or (mask >> i & 1)]


def select_by_list(selected: list | None, options: Iterable) -> list:
    return [opt for opt in options if not selected or opt in selected]


def detect_advanced_syntax(query: str) -> set[str]:
    rules = [
        ("boolean_op", r"\b(AND|OR)\b"),
        ("field_prefix", r"\w+:"),
        ("phrase", r'"[^"]*"'),
        ("must_exclude", r"(^|\s)[+\-]\w"),
        ("range", r"[\[{][^\]\}\n]+\bTO\b[^\]\}\n]+[\]}]"),
        ("set", r"\bIN\s*\[[^\]]*\]"),
        ("boost", r"\^(\d+|\d*\.\d*)"),
        ("regex", r"/[^/\n]+/"),
    ]

    matched = set()
    for name, pattern in rules:
        if re.search(pattern, query):
            matched.add(name)

    return matched


def get_expanded_query(query: str, field_name: str, prefix: bool, schema: Schema) -> Query:
    words = default_tokenizer.analyze(query) if not field_name.endswith("_raw") else query.split()
    subqueries = []
    if len(words) >= 2:
        subqueries.append((Occur.Should, Query.boost_query(Query.phrase_query(schema, field_name, words), 3)))

    and_query = []
    prefix_query = []
    for word in words:
        and_query.append((Occur.Must, Query.term_query(schema, field_name, word)))
        prefix_query.append((Occur.Must, Query.fuzzy_term_query(schema, field_name, word, 0, prefix=True)))

    subqueries.append((Occur.Should, Query.boolean_query(and_query)))
    if prefix:
        subqueries.append((Occur.Should, Query.boost_query(Query.boolean_query(prefix_query), 0.5)))

    return Query.boolean_query(subqueries)


def get_text_query(query: str | None, field_name: str, prefix: bool, index: Index, schema: Schema) -> tuple[Query, Any]:
    if query is None:
        return Query.all_query(), None

    advanced_features = detect_advanced_syntax(query)
    if not advanced_features:
        return get_expanded_query(query, field_name, prefix, schema), None

    if "field_prefix" not in advanced_features:
        query = f"{field_name}:{query}"

    return index.parse_query_lenient(
        query, default_field_names=[field_name], conjunction_by_default=True, allow_regexes=True
    )


def build_keyword_query(schema: Schema, paths: list[str], fields: list[str], mode: str) -> Query:
    if mode == "and":
        subqueries = []
        for path in paths:
            per_path = [(Occur.Should, Query.term_query(schema, field, path)) for field in fields]
            subqueries.append((Occur.Must, Query.boolean_query(per_path)))
        return Query.boolean_query(subqueries)

    subqueries = [(Occur.Should, Query.term_set_query(schema, field, paths)) for field in fields]
    return Query.boolean_query(subqueries)


def get_date_query(lower: datetime | None, upper: datetime | None, field_name: str, schema: Schema) -> Query:
    if not lower and not upper:
        return Query.all_query()

    return Query.range_query(schema, field_name, FieldType.Date, lower, upper)


def get_snippet_generators(
    searcher: Searcher, query: Query, snippet_fields: dict[str, str], schema: Schema
) -> dict[str, SnippetGenerator]:
    result = {}
    for doc_type, field in snippet_fields.items():
        gen = SnippetGenerator.create(searcher, query, schema, field)
        gen.set_max_num_chars(300)
        result[doc_type] = gen

    return result


def get_results_from_hits(
    searcher: Searcher, hits: list[tuple[Any, DocAddress]], snippet_generators: dict[str, SnippetGenerator]
) -> list[dict]:
    result = []
    for _, doc_addr in hits:
        doc = searcher.doc(doc_addr)
        entry = {key: val[0] if len(val) == 1 else val for key, val in doc.to_dict().items()}
        snippets = {}
        for doc_type, gen in snippet_generators.items():
            html = gen.snippet_from_doc(doc).to_html()
            if html.strip():
                snippets[doc_type] = html
        entry["snippets"] = snippets
        result.append(entry)
    return result


class Search(ABC):
    search_args: ClassVar[dict[str, FieldProtocol]]
    snippet_fields: ClassVar
    schema: ClassVar[Schema]
    index: ClassVar[Callable[[], Index]]
    collection: ClassVar

    @classmethod
    @abstractmethod
    def _enrich_args(cls, parsed: dict) -> dict:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def _build_query(cls, args: dict, broader: bool, fulltext: bool) -> tuple[Query, dict]:
        raise NotImplementedError

    @classmethod
    def _get_args(cls) -> dict[str, FieldProtocol]:
        return {
            "query": TextField(),
            "page": IntField(1, min=1),
            "per_page": IntField(current_app.config["SEARCH_ITEMS_PER_PAGE"], min=1, max=100),
            "search_type": OptionField({"name", "fulltext"}, "name"),
            **cls.search_args,
        }

    @classmethod
    def _parse_args(cls, args: dict | MultiDict) -> dict:
        parsed = {}
        errors = {}
        for name, field in cls._get_args().items():
            result = field.parse(args.get(name))
            if not result.ok:
                errors[name] = result.error
            else:
                parsed[name] = result.value
        if errors:
            raise BadRequest(description=str(errors))
        return cls._enrich_args(parsed)

    @classmethod
    def _search_with_fallback(
        cls, args: dict, searcher: Searcher, sort_by: str, sort_dir: str, per_page: int, page: int, fulltext: bool
    ):
        for broader in (False, True):
            query, errs = cls._build_query(args, broader, fulltext)
            if errs:
                return None, None, errs

            order_dir = Order.Desc if sort_dir == "desc" else Order.Asc
            result = searcher.search(
                query, order_by_field=sort_by, order=order_dir, limit=per_page, offset=(page - 1) * per_page
            )
            if result.count > 0:
                break

        return query, result, {}

    @classmethod
    def _search(cls, args: dict) -> tuple[list, int, dict]:
        fulltext = args["search_type"] == "fulltext"
        page = args["page"]
        per_page = args["per_page"]
        sort_by = args["sort_by"]
        sort_dir = args["sort_dir"]

        searcher = cls.index().searcher()
        query, result, errors = cls._search_with_fallback(args, searcher, sort_by, sort_dir, per_page, page, fulltext)
        if errors:
            return [], 0, errors
        snippet_generators = {}
        if fulltext:
            snippet_generators = get_snippet_generators(searcher, query, cls.snippet_fields, cls.schema)

        return get_results_from_hits(searcher, result.hits, snippet_generators), result.count, {}

    @classmethod
    def process_search(cls, req, callback=None):
        parsed = cls._parse_args(req.args)
        result, count, errors = cls._search(parsed)
        pagination = Pagination(
            page=parsed["page"],
            per_page=parsed["per_page"],
            search=True,
            found=count,
            total=cls.collection.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            url_callback=callback,
            next_rel="next",
            prev_rel="prev",
        )
        return {
            "pagination": pagination,
            "result": result,
            "errors": errors,
            **parsed,
        }
