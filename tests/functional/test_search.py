import pytest
from common.search.index import index_schema
from whoosh.filedb.filestore import RamStorage
from whoosh.index import FileIndex
from whoosh.qparser import QueryParser

from sec_certs_page.common.search.analyzer import FancyAnalyzer


def test_tokenizer():
    fa = FancyAnalyzer()
    indexed = [
        t.text
        for t in fa("BSI-AA-2017-24 is the new SHA-3 for the post-quantum age of the SuperCrypto AES256.", mode="index")
    ]
    queried = [
        t.text
        for t in fa("BSI-AA-2017-24 is the new SHA-3 for the post-quantum age of the SuperCrypto AES256.", mode="query")
    ]
    assert indexed == [
        "bsi-aa-2017-24",
        "bsi",
        "aa",
        "2017",
        "24",
        "new",
        "sha-3",
        "sha",
        "3",
        "post-quantum",
        "post",
        "quantum",
        "age",
        "supercrypto",
        "super",
        "crypto",
        "aes256",
        "aes",
        "256",
    ]
    assert queried == [
        "bsi",
        "aa",
        "2017",
        "24",
        "new",
        "sha",
        "3",
        "post",
        "quantum",
        "age",
        "super",
        "crypto",
        "aes",
        "256",
    ]
    empty = [t.text for t in fa("")]
    assert empty == []


def test_queryparser():
    parser = QueryParser("content", index_schema)
    parsed = parser.parse("Some 'BSI-DSZ-1233\" SHA-3")
    assert parsed


@pytest.fixture()
def index():
    storage = RamStorage()
    return FileIndex.create(storage, index_schema, "MAIN")


@pytest.fixture()
def reader(index):
    return index.reader()


@pytest.fixture()
def searcher(index):
    return index.searcher()


@pytest.fixture()
def writer(index):
    return index.writer()


@pytest.fixture()
def some_documents(writer):
    writer.add_document(
        dgst="12345",
        name="Some certificate name with version 1.2",
        document_type="report",
        cert_schema="cc",
        category="c",
        status="active",
        scheme="NL",
        content="""BSI-DSZ-CC-0758-2012
for
Infineon Security Controller M7892 A21 with
optional RSA2048/4096 v1.02.013, EC v1.02.013,
SHA-2 v1.01 and Toolbox v1.02.013 libraries and
with specific IC dedicated software (firmware)
from
Infineon Technologies AG""",
    )
    writer.commit()


def test_search(some_documents, searcher):
    parser = QueryParser("content", index_schema)
    assert searcher.search(parser.parse('"BSI-DSZ-CC-0758-2012"'))
    assert searcher.search(parser.parse('libraries AND "SHA-2"'))
    assert searcher.search(parser.parse("BSI"))
    assert searcher.search(parser.parse("SHA-2"))
    assert searcher.search(parser.parse("v1.02.013"))
    assert searcher.search(parser.parse("v1.02.*"))
    assert searcher.search(parser.parse('"v1.02.013"'))
    assert not searcher.search(parser.parse("v1.02.014"))
    assert not searcher.search(parser.parse("and"))
    assert not searcher.search(parser.parse('"BSI-DSZ-CC-1234-2012"'))
    assert not searcher.search(parser.parse("software NOT firmware"))
    assert not searcher.search(parser.parse("SHA-3"))
    assert not searcher.search(parser.parse('"SHA-3"'))
