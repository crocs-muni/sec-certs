import random

import pymongo
import pytest

from sec_certs_page import mongo
from sec_certs_page.common.diffs import apply_explicit_diff, fips_diff_method, render_compare
from sec_certs_page.common.objformats import freeze, load
from sec_certs_page.fips.tasks import FIPSNotifier


def test_fips_diff_renders(client):
    all_diffs = list(mongo.db.fips_diff.find({}, {"_id": True}))
    notifier = FIPSNotifier()
    for _ in range(100):
        id = random.choice(all_diffs)
        diff = load(mongo.db.fips_diff.find_one(id))
        cert = load(mongo.db.fips.find_one(diff["dgst"]))
        r = notifier.render_diff(id["_id"], cert, diff)
        assert r is not None


def test_fips_compare_render(client):
    all_ids = list(mongo.db.fips.find({}, {"_id": True}))
    for _ in range(200):
        idd_one = random.choice(all_ids)
        cert_one = load(mongo.db.fips.find_one(idd_one))
        idd_other = random.choice(all_ids)
        cert_other = load(mongo.db.fips.find_one(idd_other))
        assert render_compare(cert_one, cert_other, fips_diff_method) is not None


@pytest.mark.parametrize("dgst", ["03a3d955b8799a90", "d5b148567313dccf", "8fe1029e7f1d04f6", "0b8c4c7c81ac3255"])
def test_fips_diff_reconstruction(dgst):
    new_diff = mongo.db.fips_diff.find_one({"dgst": dgst, "type": "new"})
    change_diffs = mongo.db.fips_diff.find({"dgst": dgst, "type": "change"}).sort([("timestamp", pymongo.ASCENDING)])

    current = load(new_diff["diff"])
    for diff in change_diffs:
        current = apply_explicit_diff(current, load(diff["diff"]))
    current = freeze(current)

    actual = load(mongo.db.fips.find_one({"dgst": dgst}))
    assert dict(current) == dict(actual)
