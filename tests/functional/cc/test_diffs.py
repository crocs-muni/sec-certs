import random

import pymongo
import pytest

from sec_certs_page import mongo
from sec_certs_page.cc.tasks import CCNotifier
from sec_certs_page.common.diffs import apply_explicit_diff
from sec_certs_page.common.objformats import freeze, load


def test_cc_diff_renders(client):
    all_diffs = list(mongo.db.cc_diff.find({}, {"_id": True}))
    notifier = CCNotifier()
    for _ in range(100):
        id = random.choice(all_diffs)
        diff = load(mongo.db.cc_diff.find_one(id))
        cert = load(mongo.db.cc.find_one(diff["dgst"]))
        assert notifier.render_diff(id["_id"], cert, diff) is not None


@pytest.mark.parametrize("dgst", ["d492f0e3e19d32f6", "2ff8ceac4a6ca519", "0adbded2df213f16", "fb8945b7036e2361"])
def test_cc_diff_reconstruction(dgst):
    new_diff = mongo.db.cc_diff.find_one({"dgst": dgst, "type": "new"})
    change_diffs = mongo.db.cc_diff.find({"dgst": dgst, "type": "change"}).sort([("timestamp", pymongo.ASCENDING)])

    current = load(new_diff["diff"])
    for diff in change_diffs:
        current = apply_explicit_diff(current, load(diff["diff"]))
    current = freeze(current)

    actual = load(mongo.db.cc.find_one({"dgst": dgst}))
    assert dict(current) == dict(actual)
