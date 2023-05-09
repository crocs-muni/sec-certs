from abc import ABC, abstractmethod
from typing import ClassVar, Optional, Set, Union

from flask import current_app
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest

from ..objformats import load
from ..views import Pagination


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
        q = args.get("q", None)
        cat = args.get("cat", None)
        categories = cls.categories.copy()
        if cat is not None:
            for name, category in categories.items():
                category["selected"] = category["id"] in cat
        else:
            for category in categories.values():
                category["selected"] = True
        status = args.get("status", cls.status_default)
        if status not in cls.status_options:
            raise BadRequest(description="Invalid status.")
        sort = args.get("sort", cls.sort_default)
        if sort not in cls.sort_options:
            raise BadRequest(description="Invalid sort.")
        res = {"q": q, "page": page, "cat": cat, "categories": categories, "sort": sort, "status": status}
        return res

    @classmethod
    @abstractmethod
    def select_certs(cls, q, cat, categories, status, sort, **kwargs):
        raise NotImplementedError

    @classmethod
    def process_search(cls, req, callback=None):
        parsed = cls.parse_args(req.args)
        cursor, count = cls.select_certs(**parsed)

        page = parsed["page"]

        per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
        pagination = Pagination(
            page=page,
            per_page=per_page,
            search=True,
            found=count,
            total=cls.collection.count_documents({}),
            css_framework="bootstrap5",
            alignment="center",
            url_callback=callback,
        )
        return {
            "pagination": pagination,
            "certs": list(map(load, cursor[(page - 1) * per_page : page * per_page])),
            **parsed,
        }
