import requests
from flask.testing import FlaskClient


def test_chat_rag(logged_in: FlaskClient, mocker, clean_mongo):
    result = requests.Response()
    result.status_code = 200
    result.json = lambda: {"choices": [{"message": {"role": "assistant", "content": "This is a test response."}}]}  # type: ignore
    mocker.patch("sec_certs_page.chat.views.chat_rag", return_value=result)
    resp = logged_in.post(
        "/chat/rag/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "about": "entry",
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    assert resp.json["status"] == "ok"
    assert "This is a test response." in resp.json["response"]


def test_chat_full(logged_in: FlaskClient, mocker, clean_mongo):
    result = requests.Response()
    result.status_code = 200
    result.json = lambda: {"choices": [{"message": {"role": "assistant", "content": "This is a test response."}}]}  # type: ignore
    mocker.patch("sec_certs_page.chat.views.chat_full", return_value=result)
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "context": "both",
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    assert resp.json["status"] == "ok"
    assert "This is a test response." in resp.json["response"]


def test_chat_limit(logged_in: FlaskClient, mocker, clean_mongo):
    result = requests.Response()
    result.status_code = 200
    result.json = lambda: {"choices": [{"message": {"role": "assistant", "content": "This is a test response."}}]}  # type: ignore
    mocker.patch("sec_certs_page.chat.views.chat_full", return_value=result)
    for i in range(100):
        resp = logged_in.post(
            "/chat/full/",
            json={
                "query": [{"role": "user", "content": "What is this a certificate of?"}],
                "context": "both",
                "collection": "cc",
                "hashid": "3d1b01ce576f605d",
            },
        )
        assert resp.status_code == 200

    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "context": "both",
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 429
    assert resp.json["status"] == "error"
    assert "You have reached the request limit of 100 requests" in resp.json["message"]
