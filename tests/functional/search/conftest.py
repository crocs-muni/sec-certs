import pytest
from flask import request


@pytest.fixture
def check(app):
    def _check(search_cls, params, *, expect_ids=None, expect_count=None, id_field="dgst", broadened=None):
        with app.test_request_context(query_string=params):
            res = search_cls.process_search(request)
        if expect_ids is not None:
            ids = {r[id_field] for r in res["result"]}
            assert ids == set(expect_ids), res["errors"] or ids
        if expect_count is not None:
            assert res["pagination"].found == expect_count, res["errors"] or res["pagination"].found
        if broadened is not None:
            assert res["broadened"] is broadened
        return res

    return _check
