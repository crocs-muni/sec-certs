from datetime import datetime, timezone

import pytest
from flask import url_for

from sec_certs_page import mail, mongo
from sec_certs_page.cc.tasks import notify


@pytest.fixture(params=["3d1b01ce576f605d", "44f677892bb84ce5"])
def certificate(request):
    return mongo.db.cc.find_one({"_id": request.param})


@pytest.fixture(params=["all", "vuln"])
def subscription(user, certificate, request):
    sub = {
        "username": user[0].username,
        "timestamp": datetime.now(timezone.utc),
        "certificate": {
            "name": certificate["name"],
            "hashid": certificate["_id"],
            "type": "cc",
            "url": url_for("cc.entry", hashid=certificate["_id"]),
        },
        "updates": request.param,
        "type": "changes",
    }
    res = mongo.db.subs.insert_one(sub)
    sub["_id"] = res.inserted_id
    yield sub
    mongo.db.subs.delete_one({"_id": res.inserted_id})


def test_send_notification(user, mocker, subscription):
    user, password = user

    m = mocker.patch.object(mail, "send")
    dgst = subscription["certificate"]["hashid"]
    if subscription["updates"] == "vuln":
        pytest.skip("Skip vuln only sub.")
    diffs = list(mongo.db.cc_diff.find({"dgst": dgst}))
    notify(str(diffs[-1]["run_id"]))
    for call_args in m.call_args_list:
        message = call_args.args[0]
        if user.email in message.recipients:
            break
    else:
        assert False


@pytest.mark.slow
def test_cve_notification(user, mocker, subscription):
    dgst = subscription["certificate"]["hashid"]
    diffs = list(mongo.db.cc_diff.find({"type": "change", "dgst": dgst}))
    m = mocker.patch.object(mail, "send")

    for diff in diffs:
        vuln_diff = False
        if h := diff["diff"]["__update__"].get("heuristics"):
            for action, val in h.items():
                if "related_cves" in val:
                    vuln_diff = True
                    break
        notify(str(diff["run_id"]))
        if vuln_diff or subscription["updates"] == "all":
            assert m.call_count == 1
        else:
            assert m.call_count == 0
        m.reset_mock()


@pytest.fixture()
def subscription_new(user):
    sub = {
        "username": user[0].username,
        "timestamp": datetime.now(timezone.utc),
        "type": "new",
        "which": "cc",
    }
    res = mongo.db.subs.insert_one(sub)
    sub["_id"] = res.inserted_id
    yield sub
    mongo.db.subs.delete_one({"_id": res.inserted_id})


def test_new_certificate_notification(user, mocker, certificate, subscription_new):
    user, password = user

    dgst = certificate["_id"]
    diffs = list(mongo.db.cc_diff.find({"type": "new", "dgst": dgst}))
    m = mocker.patch.object(mail, "send")

    for diff in diffs:
        notify(str(diff["run_id"]))
        for call_args in m.call_args_list:
            message = call_args.args[0]
            if user.email in message.recipients:
                break
        else:
            assert False
