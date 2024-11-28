import pytest
from common.search.index import index_schema
from whoosh.filedb.filestore import RamStorage
from whoosh.index import FileIndex
from whoosh.reading import IndexReader
from whoosh.searching import Searcher

from sec_certs_page.common.search.analyzer import FancyAnalyzer
from sec_certs_page.common.search.query import QueryParser


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
    parser = QueryParser(["content"], index_schema)
    parsed = parser.parse('Some "BSI-DSZ-1233" SHA-3 BSI-DSZ-1234 v1.02.13*', debug=True)
    assert parsed


@pytest.fixture()
def index() -> FileIndex:
    storage = RamStorage()
    return FileIndex.create(storage, index_schema, "MAIN")


@pytest.fixture()
def reader(index) -> IndexReader:
    return index.reader()


@pytest.fixture()
def searcher(index) -> Searcher:
    return index.searcher()


@pytest.fixture()
def some_documents(index):
    with index.writer() as writer:
        one = writer.docnum
        writer.add_document(
            dgst="12345",
            name="Some certificate name with version 1.2",
            document_type="report",
            cert_schema="cc",
            cert_id="BSI-DSZ-CC-0758-2012",
            category="c",
            status="active",
            scheme="DE",
            content="""BSI-DSZ-CC-0758-2012
    for
    Infineon Security Controller M7892 A21 with
    optional RSA2048/4096 v1.02.013, EC v1.02.013,
    SHA-2 v1.01 and Toolbox v1.02.013 libraries and
    with specific IC dedicated software (firmware)
    from Infineon Technologies AG including smartcard""",
        )
        other = writer.docnum
        writer.add_document(
            dgst="5623",
            name="Other certificate",
            document_type="report",
            cert_schema="cc",
            cert_id="ANSSI-CC-2015/74",
            category="c",
            status="active",
            scheme="FR",
            content=""".Page 6 sur 15 ANSSI-CC-CER-F-07.017
    1. Le produit
    1.1. PrÃ©sentation du produit
    Le produit Ã©valuÃ© est Â« NXP JAVA OS1 ChipDoc v1.0 ICAO BAC with optional AA on
    P60D080JVC Â» dÃ©veloppÃ© par ATHENA SMARTCARD SOLUTIONS et NXP SEMICONDUCTORS. Il est
    embarquÃ© sur les microcontrÃ´leurs P60D080JVC de la sociÃ©tÃ© NXP SEMICONDUCTORS v1
    Le produit Ã©valuÃ© est de type Â« carte Ã 02 puce Â» avec et sans contact. Il implÃ©mente les fonctions
    de document de voyage Ã©lectronique conformÃ©ment aux spÃ©cifications de lâ€™organisation de
    lâ€™aviation civile internationale (OACI1""",
        )
    return one, other


def test_search(some_documents, searcher):
    infineon, nxp = some_documents
    parser = QueryParser(["content"], index_schema)
    assert len(searcher.search(parser.parse('"BSI-DSZ-CC-0758-2012"'))) == 1
    assert len(searcher.search(parser.parse('libraries AND "SHA-2"'))) == 1
    assert len(searcher.search(parser.parse("BSI"))) == 1
    assert len(searcher.search(parser.parse("SHA-2"))) == 1
    assert len(searcher.search(parser.parse("v1.02.013"))) == 1
    assert len(searcher.search(parser.parse('"v1.02.0"*'))) == 1
    assert len(searcher.search(parser.parse("v1.02.0*"))) == 1
    assert len(searcher.search(parser.parse('"v1.02.013"'))) == 1
    assert len(searcher.search(parser.parse("Athena"))) == 1
    assert len(searcher.search(parser.parse("NXP"))) == 1
    assert len(searcher.search(parser.parse("ICAO BAC"))) == 1
    assert len(searcher.search(parser.parse("smartcard"))) == 2
    assert not searcher.search(parser.parse("v1.02.014"))
    assert not searcher.search(parser.parse("and"))
    assert not searcher.search(parser.parse('"BSI-DSZ-CC-1234-2012"'))
    assert not searcher.search(parser.parse("software NOT firmware"))
    assert not searcher.search(parser.parse("SHA-3"))
    assert not searcher.search(parser.parse('"SHA-3"'))
    assert not searcher.search(parser.parse('v1.02.0* NOT "v1.02.013"'))
