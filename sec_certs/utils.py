from flask_paginate import Pagination as FlaskPagination
from functools import total_ordering


class Pagination(FlaskPagination):
    def __init__(self, found=0, **kwargs):
        self.url_callback = kwargs.get("url_callback", None)
        super().__init__(found, **kwargs)

    def page_href(self, page):
        if self.url_callback is None:
            return super().page_href(page)
        else:
            return self.url_callback(page=page, **self.args)


@total_ordering
class Smallest(object):
    def __lt__(self, other):
        return True

    def __eq__(self, other):
        if isinstance(other, Smallest):
            return True
        else:
            return False


smallest = Smallest()


@total_ordering
class Biggest(object):
    def __gt__(self, other):
        return True

    def __eq__(self, other):
        if isinstance(other, Biggest):
            return True
        else:
            return False


biggest = Biggest()
