import pytest
from flask import url_for
from flask.testing import FlaskClient
from pytest_mock import MockerFixture

from sec_certs_page import mail, mongo
from sec_certs_page.fips.tasks import notify
from sec_certs_page.notifications.tasks import send_confirmation_email


@pytest.fixture(params=["6b86b273ff34fce1", "3c365ff931ecb0e3"])
def certificate(request):
    return mongo.db.fips.find_one({"_id": request.param})


@pytest.fixture(params=["all", "vuln"])
def sub_obj(certificate, request):
    return {
        "selected": [
            {
                "name": certificate["web_data"]["module_name"],
                "hashid": certificate["_id"],
                "type": "fips",
                "url": url_for("fips.entry", hashid=certificate["_id"]),
            }
        ],
        "email": "example@example.com",
        "updates": request.param,
        "captcha": "...",
    }


@pytest.fixture
def unconfirmed_subscription(client: FlaskClient, mocker: MockerFixture, sub_obj):
    mocker.patch("sec_certs_page.common.views.validate_captcha")
    mocker.patch("flask_wtf.csrf.validate_csrf")
    mocker.patch("dramatiq.Actor.send")
    client.post("/notify/subscribe/", json=sub_obj)
    subscription = mongo.db.subs.find_one({"email": sub_obj["email"]})
    yield subscription
    mongo.db.subs.delete_one({"_id": subscription["_id"]})


@pytest.fixture
def confirmed_subscription(client: FlaskClient, unconfirmed_subscription):
    client.get(f"/notify/confirm/{unconfirmed_subscription['token']}")
    subscription = mongo.db.subs.find_one({"_id": unconfirmed_subscription["_id"]})
    yield subscription
    mongo.db.subs.delete_one({"_id": subscription["_id"]})


def test_send_notification(app, mocker, confirmed_subscription):
    m = mocker.patch.object(mail, "send")
    dgst = confirmed_subscription["certificate"]["hashid"]
    if confirmed_subscription["updates"] == "vuln":
        pytest.skip("Skip vuln only sub.")
    diffs = list(mongo.db.fips_diff.find({"dgst": dgst}))
    notify(str(diffs[-1]["run_id"]))
    for call_args in m.call_args_list:
        message = call_args.args[0]
        if confirmed_subscription["email"] in message.recipients:
            break
    else:
        assert False


@pytest.mark.slow
def test_cve_notification(app, mocker, confirmed_subscription):
    dgst = confirmed_subscription["certificate"]["hashid"]
    diffs = list(mongo.db.fips_diff.find({"type": "change", "dgst": dgst}))
    m = mocker.patch.object(mail, "send")

    for diff in diffs:
        vuln_diff = False
        if h := diff["diff"]["__update__"].get("heuristics"):
            for action, val in h.items():
                if "related_cves" in val:
                    vuln_diff = True
                    break
        notify(str(diff["run_id"]))
        if vuln_diff or confirmed_subscription["updates"] == "all":
            assert m.call_count == 1
        else:
            assert m.call_count == 0
        m.reset_mock()
