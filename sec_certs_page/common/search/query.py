import operator
import sys
import time
from abc import ABC, abstractmethod
from datetime import datetime
from functools import reduce
from typing import ClassVar, Iterable, List, Mapping, Optional, Set, Tuple, Union

import sentry_sdk
from flask import Request, current_app
from pymongo.collection import Collection
from pymongo.cursor import Cursor
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest
from whoosh import highlight, query
from whoosh.qparser import Plugin
from whoosh.qparser import QueryParser as OriginalQueryParser
from whoosh.qparser import RegexTagger, TaggingPlugin, attach, plugins, syntax
from whoosh.query import Query
from whoosh.searching import Results, ResultsPage
from whoosh.util.text import rcompile

from ... import get_searcher
from ..objformats import load
from ..views import Pagination, entry_file_path
from .index import index_schema


class QueryParser(OriginalQueryParser):
    """Custom MultiFieldParser with a Verbatim phrase plugin."""

    def __init__(self, fieldnames, schema, fieldboosts=None, **kwargs):
        plugs = [
            plugins.WhitespacePlugin(),
            plugins.SingleQuotePlugin(),
            plugins.FieldsPlugin(),
            WildcardPlugin(),
            VerbatimPhrasePlugin(),
            plugins.RangePlugin(),
            plugins.GroupPlugin(),
            plugins.OperatorsPlugin(),
            plugins.BoostPlugin(),
            plugins.EveryPlugin(),
            plugins.MultifieldPlugin(fieldnames, fieldboosts=fieldboosts),
        ]
        super().__init__(None, schema, plugs, **kwargs)

    def term_query(self, fieldname, text, termclass, boost=1.0, tokenize=True, removestops=True):
        """Returns the appropriate query object for a single term in the query
        string.
        """

        if self.schema and fieldname in self.schema:
            field = self.schema[fieldname]

            # If this field type wants to parse queries itself, let it do so
            # and return early
            if field.self_parsing():
                try:
                    q = field.parse_query(fieldname, text, boost=boost)
                    return q
                except:  # noqa
                    e = sys.exc_info()[1]
                    return query.error_query(e)

            # Otherwise, ask the field to process the text into a list of
            # tokenized strings
            if termclass in (query.Prefix, query.Wildcard):
                texts = list(field.process_text(text, mode="phrase", tokenize=tokenize, removestops=removestops))
            else:
                texts = list(field.process_text(text, mode="query", tokenize=tokenize, removestops=removestops))
            # If the analyzer returned more than one token, use the field's
            # multitoken_query attribute to decide what query class, if any, to
            # use to put the tokens together
            if len(texts) > 1:
                return self.multitoken_query(field.multitoken_query, texts, fieldname, termclass, boost)

            # It's possible field.process_text() will return an empty list (for
            # example, on a stop word)
            if not texts:
                return None
            text = texts[0]

        return termclass(fieldname, text, boost=boost)


class VerbatimPhrasePlugin(Plugin):
    """Adds the ability to specify phrase queries inside double quotes."""

    # Didn't use TaggingPlugin because I need to add slop parsing at some
    # point

    # Expression used to find words if a schema isn't available
    wordexpr = rcompile(r"\S+")

    class PhraseNode(syntax.TextNode):
        def __init__(self, text, textstartchar, slop=1):
            syntax.TextNode.__init__(self, text)
            self.textstartchar = textstartchar
            self.slop = slop

        def r(self):
            return "%s %r~%s" % (self.__class__.__name__, self.text, self.slop)

        def apply(self, fn):
            return self.__class__(self.type, [fn(node) for node in self.nodes], slop=self.slop, boost=self.boost)

        def query(self, parser):
            text = self.text
            fieldname = self.fieldname or parser.fieldname

            # We want to process the text of the phrase into "words" (tokens),
            # and also record the startchar and endchar of each word

            sc = self.textstartchar
            if parser.schema and fieldname in parser.schema:
                field = parser.schema[fieldname]
                if field.analyzer:
                    # We have a field with an analyzer, so use it to parse
                    # the phrase into tokens
                    tokens = field.tokenize(text, mode="phrase", chars=True)
                    words = []
                    char_ranges = []
                    for t in tokens:
                        words.append(t.text)
                        char_ranges.append((sc + t.startchar, sc + t.endchar))
                else:
                    # We have a field but it doesn't have a format object,
                    # for some reason (it's self-parsing?), so use process_text
                    # to get the texts (we won't know the start/end chars)
                    words = list(field.process_text(text, mode="phrase"))
                    char_ranges = [(None, None)] * len(words)
            else:
                # We're parsing without a schema, so just use the default
                # regular expression to break the text into words
                words = []
                char_ranges = []
                for match in VerbatimPhrasePlugin.wordexpr.finditer(text):
                    words.append(match.group(0))
                    char_ranges.append((sc + match.start(), sc + match.end()))

            qclass = parser.phraseclass
            q = qclass(fieldname, words, slop=self.slop, boost=self.boost, char_ranges=char_ranges)
            return attach(q, self)

    class PhraseTagger(RegexTagger):
        def create(self, parser, match):
            text = match.group("text")
            textstartchar = match.start("text")
            slopstr = match.group("slop")
            slop = int(slopstr) if slopstr else 1
            return VerbatimPhrasePlugin.PhraseNode(text, textstartchar, slop)

    def __init__(self, expr='"(?P<text>.*?)"(~(?P<slop>[1-9][0-9]*))?'):
        self.expr = expr

    def taggers(self, parser):
        return [(self.PhraseTagger(self.expr), 0)]


class WildcardPlugin(TaggingPlugin):
    # \u055E = Armenian question mark
    # \u061F = Arabic question mark
    # \u1367 = Ethiopic question mark
    qmarks = "?\u055e\u061f\u1367"
    expr = "(?P<text>[*%s])" % qmarks

    def filters(self, parser):
        # Run early, but definitely before multifield plugin
        return [(self.do_wildcards, 50)]

    def do_wildcards(self, parser, group):
        i = 0
        while i < len(group):
            node = group[i]
            if isinstance(node, self.WildcardNode):
                if i < len(group) - 1 and group[i + 1].is_text():
                    nextnode = group.pop(i + 1)
                    node.text += nextnode.text
                if i > 0 and group[i - 1].is_text():
                    prevnode = group.pop(i - 1)
                    node.text = prevnode.text + node.text
                else:
                    i += 1
            else:
                if isinstance(node, syntax.GroupNode):
                    self.do_wildcards(parser, node)
                i += 1

        for i in range(len(group)):
            node = group[i]
            if isinstance(node, self.WildcardNode):
                text = node.text
                if len(text) > 1 and not any(qm in text for qm in self.qmarks):
                    if text.find("*") == len(text) - 1:
                        newnode = self.PrefixNode(text[:-1])
                        newnode.startchar = node.startchar
                        newnode.endchar = node.endchar
                        group[i] = newnode
        return group

    class PrefixNode(syntax.TextNode):
        qclass = query.Prefix

        def r(self):
            return "%r*" % self.text

    class WildcardNode(syntax.TextNode):
        # Note that this node inherits tokenize = False from TextNode,
        # so the text in this node will not be analyzed... just passed
        # straight to the query

        qclass = query.Wildcard

        def r(self):
            return "Wild %r" % self.text

    nodetype = WildcardNode


class BasicSearch(ABC):
    status_options: ClassVar[Set[str]]
    status_default: ClassVar[str]
    sort_options: ClassVar[Set[str]]
    sort_default: ClassVar[str]
    categories: ClassVar[dict[str, dict]]
    collection: ClassVar

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        """Parse the request into validated args."""
        try:
            page = int(args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        if page < 1:
            raise BadRequest(description="Invalid page number, must be >= 1.")
        try:
            per_page = int(args.get("per_page", current_app.config["SEARCH_ITEMS_PER_PAGE"]))
        except ValueError:
            raise BadRequest(description="Invalid per_page value.")
        q = args.get("q", None)
        cat = args.get("cat", None)
        advanced = False
        categories = cls.categories.copy()
        if cat is not None:
            for name, category in categories.items():
                category["selected"] = category["id"] in cat
                if category["id"] not in cat:
                    advanced = True
        else:
            for category in categories.values():
                category["selected"] = True
        status = args.get("status", cls.status_default)
        if status not in cls.status_options:
            raise BadRequest(description="Invalid status.")
        if status != cls.status_default:
            advanced = True
        sort = args.get("sort", cls.sort_default)
        if sort not in cls.sort_options:
            raise BadRequest(description="Invalid sort.")
        if sort != cls.sort_default:
            advanced = True
        res = {
            "q": q,
            "page": page,
            "per_page": per_page,
            "cat": cat,
            "categories": categories,
            "sort": sort,
            "status": status,
            "advanced": advanced,
        }
        return res

    @classmethod
    @abstractmethod
    def select_certs(
        cls, q, cat, categories, status, sort, **kwargs
    ) -> Tuple[Cursor[Mapping], int, List[Optional[datetime]]]:
        raise NotImplementedError

    @classmethod
    def process_search(cls, req, callback=None):
        parsed = cls.parse_args(req.args)
        cursor, count, timeline = cls.select_certs(**parsed)

        page = parsed["page"]

        per_page = parsed["per_page"]
        pagination = Pagination(
            page=page,
            per_page=per_page,
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
            "certs": list(map(load, cursor[(page - 1) * per_page : page * per_page])),
            "timeline": timeline,
            **parsed,
        }


class FulltextSearch(ABC):
    schema: ClassVar[str]
    status_options: ClassVar[Set[str]]
    status_default: ClassVar[str]
    type_options: ClassVar[Set[str]]
    type_default: ClassVar[str]
    categories: ClassVar[dict[str, dict]]
    collection: ClassVar
    doc_dir: ClassVar[str]

    @classmethod
    def parse_args(cls, args: Union[dict, MultiDict]) -> dict[str, Optional[Union[int, str]]]:
        categories = cls.categories.copy()
        try:
            page = int(args.get("page", 1))
        except ValueError:
            raise BadRequest(description="Invalid page number.")
        if page < 1:
            raise BadRequest(description="Invalid page number, must be >= 1.")
        try:
            per_page = int(args.get("per_page", current_app.config["SEARCH_ITEMS_PER_PAGE"]))
        except ValueError:
            raise BadRequest(description="Invalid per_page value.")
        q = args.get("q", None)
        cat = args.get("cat", None)
        advanced = False
        if cat is not None:
            for name, category in categories.items():
                category["selected"] = category["id"] in cat
                if category["id"] not in cat:
                    advanced = True
        else:
            for category in categories.values():
                category["selected"] = True

        document_type = args.get("type", cls.type_default)
        if document_type not in cls.type_options:
            raise BadRequest(description="Invalid type.")
        if document_type != cls.type_default:
            advanced = True

        status = args.get("status", cls.status_default)
        if status not in cls.status_options:
            raise BadRequest(description="Invalid status.")
        if status != cls.status_default:
            advanced = True
        res = {
            "q": q,
            "page": page,
            "per_page": per_page,
            "cat": cat,
            "categories": categories,
            "status": status,
            "document_type": document_type,
            "advanced": advanced,
        }
        return res

    @classmethod
    def select_items(
        cls, q, cat, categories, status, document_type, page=None, **kwargs
    ) -> Tuple[Union[Results, ResultsPage], int, Query]:
        q_filter = query.Term("cert_schema", cls.schema)
        cat_terms = []
        for name, category in categories.items():
            if category["selected"]:
                cat_terms.append(query.Term("category", category["id"]))
        q_filter &= reduce(operator.or_, cat_terms)
        if document_type != "any":
            q_filter &= query.Term("document_type", document_type)
        if status.lower() != "any":
            q_filter &= query.Term("status", status)
        if "scheme" in kwargs and kwargs["scheme"] != "any":
            q_filter &= query.Term("scheme", kwargs["scheme"])

        per_page = kwargs["per_page"]

        parser = QueryParser(
            fieldnames=["name", "cert_id", "content"],
            schema=index_schema,
            fieldboosts={"name": 2, "cert_id": 4, "content": 1},
        )
        qr = parser.parse(q)
        with sentry_sdk.start_span(op="whoosh.get_searcher", description="Get whoosh searcher"):
            searcher = get_searcher()
        with sentry_sdk.start_span(op="whoosh.search", description="Search"):
            if page is None:
                res = searcher.search(qr, filter=q_filter, limit=None, scored=False)
            else:
                res = searcher.search_page(qr, pagenum=page, filter=q_filter, pagelen=per_page)
        return res, len(res), qr

    @classmethod
    def select_certs(cls, q, cat, categories, status, document_type, **kwargs) -> Tuple[Iterable[Mapping], int]:
        res, count, qr = cls.select_items(q, cat, categories, status, document_type, **kwargs)
        dgsts = set(map(operator.itemgetter("dgst"), res))
        certs = list(map(lambda dgst: load(cls.collection.find_one({"_id": dgst})), dgsts))
        return certs, len(certs)

    @classmethod
    def process_search(cls, req: Request):
        parsed = cls.parse_args(req.args)
        if parsed["q"] is None:
            return {"pagination": None, "results": [], **parsed}
        res, count, qr = cls.select_items(**parsed)

        page = parsed["page"]
        per_page = parsed["per_page"]

        res.results.fragmenter.charlimit = None
        res.results.fragmenter.maxchars = 300
        res.results.fragmenter.surround = 40
        res.results.order = highlight.SCORE
        hf = Formatter()
        res.results.formatter = hf
        runtime = res.results.runtime
        results = []
        highlite_start = time.perf_counter()
        with sentry_sdk.start_span(op="whoosh.highlight", description="Highlight results"):
            for hit in res:
                dgst = hit["dgst"]
                cert = cls.collection.find_one({"_id": dgst})
                entry = {"hit": hit, "cert": cert}
                fpath = entry_file_path(dgst, current_app.config[cls.doc_dir], hit["document_type"], "txt")
                try:
                    with open(fpath) as f:
                        contents = f.read()
                    with sentry_sdk.start_span(op="whoosh.highlight_one", description="Highlight one hit."):
                        hlt = hit.highlights("content", text=contents)
                    entry["highlights"] = hlt
                except FileNotFoundError:
                    pass
                results.append(entry)
        highlite_runtime = time.perf_counter() - highlite_start

        pagination = Pagination(
            page=page,
            per_page=per_page,
            search=True,
            found=count,
            total=cls.collection.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            next_rel="next",
            prev_rel="prev",
        )
        return {
            "pagination": pagination,
            "results": results,
            "runtime": runtime,
            "highlight_runtime": highlite_runtime,
            **parsed,
            "query": qr,
        }


class Formatter(highlight.HtmlFormatter):
    """Custom HTML formatter for highlighting search results."""

    def __init__(self):
        super().__init__(between="<br/>")
        self.wrap_tag = "span"
        self.wrap_class = "result-fragment"
        self.surround = '<span class="text-muted">...</span>'

    def format(self, fragments, replace=False):
        """Returns a formatted version of the given text, using a list of
        :class:`Fragment` objects.
        """

        formatted = [self.format_fragment(f, replace=replace) for f in fragments]
        wrapped = [
            f'<{self.wrap_tag} class="{self.wrap_class}" data-start="{frag.startchar}" data-end="{frag.endchar}">{text}</{self.wrap_tag}>'
            for frag, text in zip(fragments, formatted)
        ]
        surrounded = [f"{self.surround}{text}{self.surround}" for text in wrapped]
        return self.between.join(surrounded)
