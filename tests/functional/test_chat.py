import json

import requests
from flask.testing import FlaskClient


def _sse_stream(*deltas, tail=None, tail_exception=None):
    class FakeStream:
        status_code = 200

        def iter_lines(self, decode_unicode=False):
            for delta in deltas:
                yield "data: " + json.dumps({"choices": [{"delta": {"content": delta}}]})
            if tail_exception is not None:
                raise tail_exception
            if tail is not None:
                yield "data: " + json.dumps(tail)
            yield "data: [DONE]"

        def close(self):
            pass

    return FakeStream()


def test_chat_full(logged_in: FlaskClient, mocker, clean_mongo):
    mocker.patch(
        "sec_certs_page.chat.views.chat_full",
        side_effect=lambda *a, **k: _sse_stream("This is ", "a test response."),
    )
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "documents": ["report", "target"],
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    body = resp.get_data(as_text=True)
    assert "This is " in body
    assert "a test response." in body
    assert "event: done" in body


def test_chat_full_profile(logged_in: FlaskClient, mocker, clean_mongo):
    mocker.patch(
        "sec_certs_page.chat.views.chat_full",
        side_effect=lambda *a, **k: _sse_stream("This is a test response."),
    )
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a profile of?"}],
            "documents": ["profile"],
            "collection": "pp",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"


def test_chat_full_invalid_documents(logged_in: FlaskClient, mocker, clean_mongo):
    mocker.patch(
        "sec_certs_page.chat.views.chat_full",
        side_effect=lambda *a, **k: _sse_stream("This is a test response."),
    )
    for documents in ("report", ["../../secret"], ["report", "bad"]):
        resp = logged_in.post(
            "/chat/full/",
            json={
                "query": [{"role": "user", "content": "What is this a certificate of?"}],
                "documents": documents,
                "collection": "cc",
                "hashid": "3d1b01ce576f605d",
            },
        )
        assert resp.status_code == 400
        assert resp.json["status"] == "error"
        assert "Invalid documents" in resp.json["message"]


def test_chat_full_no_documents(logged_in: FlaskClient, mocker, clean_mongo):
    chat_mock = mocker.patch(
        "sec_certs_page.common.ai.chat.chat_with_model",
        side_effect=lambda *a, **k: _sse_stream("A general answer."),
    )
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is Common Criteria?"}],
            "documents": [],
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    assert resp.mimetype == "text/event-stream"
    assert "A general answer." in resp.get_data(as_text=True)
    system_addition = chat_mock.call_args.args[2]
    assert "no certification documents for this item are available" in system_addition.lower()


def test_chat_full_invalid_hashid(logged_in: FlaskClient, clean_mongo):
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "documents": ["report", "target"],
            "collection": "cc",
            "hashid": "0000000000000000",
        },
    )
    assert resp.status_code == 400
    assert resp.json["status"] == "error"
    assert "Invalid hashid" in resp.json["message"]


def test_chat_full_unavailable_document(logged_in: FlaskClient, mocker, clean_mongo):
    chat_mock = mocker.patch("sec_certs_page.common.ai.chat.chat_with_model")
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "documents": ["report"],
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 400
    assert resp.json["status"] == "error"
    assert "not available" in resp.json["message"]
    chat_mock.assert_not_called()


def test_chat_full_upstream_failure(logged_in: FlaskClient, mocker, clean_mongo):
    class FailedResponse:
        status_code = 502

        def close(self):
            pass

    mocker.patch("sec_certs_page.chat.views.chat_full", return_value=FailedResponse())
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "documents": ["report", "target"],
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 502
    assert resp.json["status"] == "error"
    assert "Chat request failed" in resp.json["message"]


def test_chat_full_stream_error(logged_in: FlaskClient, mocker, clean_mongo):
    mocker.patch(
        "sec_certs_page.chat.views.chat_full",
        side_effect=lambda *a, **k: _sse_stream(
            "Partial", tail_exception=requests.RequestException("connection reset")
        ),
    )
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "documents": ["report", "target"],
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Partial" in body
    assert "event: error" in body
    assert "event: done" not in body


def test_chat_full_error_chunk(logged_in: FlaskClient, mocker, clean_mongo):
    mocker.patch(
        "sec_certs_page.chat.views.chat_full",
        side_effect=lambda *a, **k: _sse_stream(tail={"error": {"message": "Model overloaded."}}),
    )
    resp = logged_in.post(
        "/chat/full/",
        json={
            "query": [{"role": "user", "content": "What is this a certificate of?"}],
            "documents": ["report", "target"],
            "collection": "cc",
            "hashid": "3d1b01ce576f605d",
        },
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "event: error" in body
    assert "Model overloaded." in body
    assert "event: done" not in body


def test_chat_limit(logged_in: FlaskClient, mocker, clean_mongo):
    mocker.patch(
        "sec_certs_page.chat.views.chat_full",
        side_effect=lambda *a, **k: _sse_stream("This is a test response."),
    )
    for i in range(100):
        resp = logged_in.post(
            "/chat/full/",
            json={
                "query": [{"role": "user", "content": "What is this a certificate of?"}],
                "documents": ["report", "target"],
                "collection": "cc",
                "hashid": "3d1b01ce576f605d",
            },
        )
        assert resp.status_code == 200
        resp.get_data()

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
