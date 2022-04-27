import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from flask.testing import FlaskClient

from sec_certs_page import app


def test_docs_upload(client: FlaskClient):
    index_text = "This is a test."
    with TemporaryDirectory() as tmpdir:
        index_file = Path(tmpdir) / "index.html"
        index_file.write_text(index_text)
        zip_file = Path(tmpdir) / "docs.zip"
        with zipfile.ZipFile(zip_file, "w") as z:
            z.write(index_file, index_file.name)
        with zip_file.open("rb") as z:
            resp = client.post(f"/docs/upload?token={app.config['DOCS_AUTH_TOKEN']}", data={"data": z})
        assert resp.status_code == 200

    resp = client.get("/docs/index.html")
    assert resp.status_code == 200
    assert resp.data == index_text.encode()
