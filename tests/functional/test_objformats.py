import json
from pathlib import Path

import pytest
from jsondiff import diff
from sec_certs.sample.cc import CCCertificate

from sec_certs_page.common.objformats import ObjFormat, WorkingFormat, freeze, unfreeze


@pytest.fixture(scope="module")
def cert1():
    test_path = Path(__file__).parent / "data" / "cert1.json"
    with test_path.open() as f:
        return test_path, json.load(f)


@pytest.fixture(scope="module")
def cert2():
    test_path = Path(__file__).parent / "data" / "cert2.json"
    with test_path.open() as f:
        return test_path, json.load(f)


def test_load_cert(cert1):
    test_path, cert_data = cert1
    cert = CCCertificate.from_json(test_path)
    storage_format = ObjFormat(cert).to_raw_format().to_working_format().to_storage_format()
    obj_format = storage_format.to_working_format().to_raw_format().to_obj_format()
    assert cert == obj_format.get()

    # Ditch this, it is non-deterministic and making it deterministic would be quite hard.
    # json_mapping = storage_format.to_json_mapping()
    # assert json_mapping == cert_data


@pytest.mark.xfail(reason="Storage format is lossy for non-str dict keys.")
def test_diff(cert1, cert2):
    d = diff(cert1[1], cert2[1], syntax="explicit")
    working = WorkingFormat(d)
    working.to_raw_format().get()
    working_back = working.to_storage_format().to_working_format().get()
    assert working.get() == unfreeze(working_back)


def test_freeze_unfreeze(cert1, cert2):
    d = diff(cert1[1], cert2[1], syntax="explicit")

    df = freeze(d)
    duf = unfreeze(df)

    assert d == duf
