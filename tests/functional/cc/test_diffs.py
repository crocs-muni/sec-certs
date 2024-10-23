import random

import pymongo
import pytest

from sec_certs_page import mongo
from sec_certs_page.cc.tasks import CCNotifier
from sec_certs_page.common.diffs import apply_explicit_diff, render_compare
from sec_certs_page.common.objformats import freeze, load


def test_cc_diff_renders(client):
    all_diffs = list(mongo.db.cc_diff.find({}, {"_id": True}))
    notifier = CCNotifier()
    for _ in range(100):
        id = random.choice(all_diffs)
        diff = load(mongo.db.cc_diff.find_one(id))
        cert = load(mongo.db.cc.find_one(diff["dgst"]))
        assert notifier.render_diff(id["_id"], cert, diff) is not None


def test_cc_compare_render(client):
    all_ids = list(mongo.db.cc.find({}, {"_id": True}))
    for _ in range(100):
        idd_one = random.choice(all_ids)
        cert_one = load(mongo.db.cc.find_one(idd_one))
        idd_other = random.choice(all_ids)
        cert_other = load(mongo.db.cc.find_one(idd_other))
        assert render_compare(cert_one, cert_other, []) is not None


@pytest.mark.parametrize("dgst", ["1412d1d9e0d553c1", "44f677892bb84ce5", "f1174ac2e100bc5c", "f0c22e3e4abad667"])
def test_cc_diff_reconstruction(dgst):
    new_diff = mongo.db.cc_diff.find_one({"dgst": dgst, "type": "new"})
    change_diffs = mongo.db.cc_diff.find({"dgst": dgst, "type": "change"}).sort([("timestamp", pymongo.ASCENDING)])

    current = load(new_diff["diff"])
    for diff in change_diffs:
        current = apply_explicit_diff(current, load(diff["diff"]))
    current = freeze(current)

    actual = load(mongo.db.cc.find_one({"dgst": dgst}))
    assert dict(current) == dict(actual)
