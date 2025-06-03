from datetime import datetime

from flask import current_app

from sec_certs_page.cc.tasks import update_kb
from sec_certs_page.common.webui import (
    chat_with_model,
    files_for_hashid,
    get_file_content,
    get_file_data_content,
    get_file_metadata,
    get_knowledge_base,
    get_knowledge_bases,
    list_files,
)


def test_file_lookup(app):
    file_id = "4d9868ff-fc25-45aa-b037-a09a22c221c1"
    meta = get_file_metadata(file_id)
    content = get_file_content(file_id)
    data = get_file_data_content(file_id)
    print(meta)
    # print(content)
    # print(data)


def test_update(app):
    update_kb([("f6aad6ac7a2f5f2d", "report", None)])


def test_file_list(app):
    files_for_hashid("158bbd5ded66f785")


def test_kb(app):
    for collection in ("CC", "FIPS", "PP"):
        for document in ("REPORTS", "TARGETS"):
            kbid = current_app.config.get(f"WEBUI_COLLECTION_{collection}_{document}", None)
            if kbid is not None:
                kb = get_knowledge_base(kbid)
                print(f"Knowledge Base {collection} {document}: {len(kb['files'])} files")


def test_chat(app):
    res = chat_with_model(
        [
            {
                "role": "user",
                "content": "What is the Common Criteria?",
            }
        ]
    )
    print(res.json())

    res = chat_with_model(
        [
            {
                "role": "user",
                "content": "Describe the contents of the provided certification report.",
            }
        ],
        files=["4d9868ff-fc25-45aa-b037-a09a22c221c1"],
    )
    print(res.json())
