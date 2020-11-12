from flask_paginate import Pagination as FlaskPagination


class Pagination(FlaskPagination):
    def __init__(self, found=0, **kwargs):
        self.url_callback = kwargs.get("url_callback", None)
        super().__init__(found, **kwargs)

    def page_href(self, page):
        if self.url_callback is None:
            return super().page_href(page)
        else:
            return self.url_callback(page=page, **self.args)
