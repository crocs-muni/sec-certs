import json
from pathlib import Path

from sec_certs.sample.common_criteria import CommonCriteriaCert

from sec_certs_page.common.objformats import ObjFormat


def test_load_cert():
    test_path = Path(__file__).parent / "data" / "cert.json"
    with test_path.open() as f:
        cert_data = json.load(f)
    cert = CommonCriteriaCert.from_json(test_path)
    storage_format = ObjFormat(cert).to_raw_format().to_working_format().to_storage_format()
    obj_format = storage_format.to_working_format().to_raw_format().to_obj_format()
    assert cert == obj_format.get()

    json_mapping = storage_format.to_json_mapping()
    assert json_mapping == cert_data
