from flask.testing import FlaskClient
from pytest_mock import MockerFixture


def test_send_feedback(client: FlaskClient, mocker: MockerFixture):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    m = mocker.patch("pymongo.collection.Collection.insert_one")
    feedback_obj = {"element": "test-element",
                    "comment": "test comment",
                    "path": "/cc/some_path"}
    resp = client.post("/feedback/", json=feedback_obj)
    assert resp.status_code == 200
    assert resp.json == {"status": "OK"}
    m.assert_called_once()


def test_bad_feedback(client: FlaskClient, mocker: MockerFixture):
    mocker.patch("flask_wtf.csrf.validate_csrf")
    feedback_obj = {"element": "test-element",
                    "path": "/cc/some_path"}
    resp = client.post("/feedback/", json=feedback_obj)
    assert resp.status_code == 400
    feedback_obj = {"element": "a" * 1000,
                    "comment": "test comment",
                    "path": "/cc/some_path"}
    resp = client.post("/feedback/", json=feedback_obj)
    assert resp.status_code == 400
