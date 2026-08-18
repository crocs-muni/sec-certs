"""
Tests of algorithm extraction from security policy tables.

These build `DocumentTable` instances directly, so they exercise the whole selection and matching logic
without needing docling installed or a real policy on disk.
"""

from __future__ import annotations

import json
from importlib.resources import as_file, files

import pytest
import tests.data.fips.tables

from sec_certs.converter import has_docling
from sec_certs.document.base import DocumentTable
from sec_certs.utils.fips_tables import canonical_id, extract_algorithms_from_tables, normalize

GOLDEN_DGST = "20fa0bcc74ce3b21"

ALG_HEADER = (("Algorithm", "Cert. #"),)


def table(
    rows: tuple[tuple[str, ...], ...],
    *,
    header: tuple[tuple[str, ...], ...] = (),
    caption: str | None = None,
    pages: tuple[int, ...] = (1,),
    is_index: bool = False,
) -> DocumentTable:
    return DocumentTable(rows=rows, header=header, caption=caption, pages=pages, is_index=is_index)


def glossary() -> DocumentTable:
    """A table that must never be picked as an algorithm table."""
    return table(
        (("AES", "Advanced Encryption Standard"), ("TLS", "Transport Layer Security")),
        header=(("Term", "Definition"),),
        caption="Table 1: Terms and Definitions",
    )


class TestSelection:
    def test_caption_selects_the_table(self):
        tables = [
            glossary(),
            table((("AES", "#1234"),), header=(("Algorithm", "Standard"),), caption="Table 4: Approved Algorithms"),
        ]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234"}
        assert [hit.selected_by for hit in result.hits] == ["caption"]
        assert not result.used_fallback

    def test_header_selects_the_table_without_a_caption(self):
        tables = [glossary(), table((("AES", "#1234"),), header=ALG_HEADER)]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234"}
        assert [hit.selected_by for hit in result.hits] == ["header"]

    def test_unselected_tables_do_not_contribute(self):
        """The glossary carries a marked number, which must not be picked up while it is not selected."""
        noise = table(
            (("Reference", "Cert. #9999 in another module"),),
            header=(("Term", "Definition"),),
            caption="Table 1: Terms and Definitions",
        )
        tables = [noise, table((("AES", "#1234"),), header=ALG_HEADER)]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234"}

    def test_first_row_stands_in_for_a_missing_header(self):
        tables = [glossary(), table((("Algorithm", "Cert. #"), ("AES", "#1234")))]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234"}
        assert [hit.selected_by for hit in result.hits] == ["header"]

    def test_body_content_alone_does_not_select(self):
        """Algorithm names in the body are not evidence that a table lists certificate numbers."""
        tables = [table((("AES", "128"), ("SHA-256", "256")), header=(("Cipher", "Key size"),))]

        result = extract_algorithms_from_tables(tables)

        assert result.used_fallback  # nothing was selected, so everything got scanned strictly
        assert result.algorithms == set()

    def test_continuation_table_is_selected_by_its_repeated_header(self):
        """A table whose header alone says nothing is still reached through the one that has a caption."""
        header = (("Function", "Reference"),)
        tables = [
            table((("AES", "Cert. #1234"),), header=header, caption="Table 4: Approved Algorithms", pages=(4,)),
            table((("SHA", "Cert. #1235"),), header=header, pages=(5,)),
        ]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234", "#1235"}
        assert [hit.selected_by for hit in result.hits] == ["caption", "continuation"]

    def test_repeated_matching_header_is_selected_on_its_own(self):
        """The common case: a continuation repeats a header that already matches by itself."""
        tables = [
            table((("AES", "#1234"),), header=ALG_HEADER, caption="Table 4: Approved Algorithms", pages=(4,)),
            table((("SHA", "#1235"),), header=ALG_HEADER, pages=(5,)),
        ]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234", "#1235"}
        assert [hit.selected_by for hit in result.hits] == ["caption", "header"]

    def test_continuation_needs_a_matching_header(self):
        tables = [
            table((("AES", "#1234"),), header=ALG_HEADER, caption="Table 4: Approved Algorithms", pages=(4,)),
            table((("Windows 10", "x64"),), header=(("Platform", "Architecture"),), pages=(5,)),
        ]

        result = extract_algorithms_from_tables(tables)

        assert [hit.selected_by for hit in result.hits] == ["caption"]

    def test_empty_tables_are_not_candidates(self):
        result = extract_algorithms_from_tables([DocumentTable(), glossary()])

        assert result.n_tables == 1


class TestIndexTables:
    def test_index_table_contributes_nothing(self):
        """A list-of-tables entry matches every caption hint and ends in a page number."""
        index = table(
            (
                ("Table 4: Approved Algorithms ....... 12",),
                ("Table 5: Security Functions ....... 15",),
            ),
            is_index=True,
        )
        tables = [index, table((("AES", "#1234"),), header=ALG_HEADER)]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#1234"}
        assert result.n_tables == 1

    def test_index_table_does_not_suppress_the_fallback(self):
        """Dropping the index must not look like 'a table matched', or the fallback would never fire."""
        index = table((("Table 4: Approved Algorithms ....... 12",),), is_index=True)
        tables = [index, table((("AES", "Cert. #1234"),), header=(("Cipher", "Notes"),))]

        result = extract_algorithms_from_tables(tables)

        assert result.used_fallback
        assert result.algorithms == {"#1234"}

    def test_document_of_only_index_tables_yields_nothing(self):
        index = table((("Table 4: Approved Algorithms ....... 12",),), is_index=True)

        result = extract_algorithms_from_tables([index])

        assert result.algorithms == set()
        assert result.n_tables == 0


class TestFallback:
    def test_fallback_fires_only_when_nothing_matched(self):
        tables = [glossary(), table((("AES", "Cert. #1234"),), header=(("Cipher", "Notes"),))]

        result = extract_algorithms_from_tables(tables)

        assert result.used_fallback
        assert result.algorithms == {"#1234"}

    def test_fallback_ignores_bare_numbers(self):
        """Without a marker, a number in an unrecognized table could be anything."""
        tables = [table((("Key size", "128"), ("Year", "2018"), ("Rounds", "10")), header=(("Property", "Value"),))]

        result = extract_algorithms_from_tables(tables)

        assert result.used_fallback
        assert result.algorithms == set()


class TestIdMatching:
    @pytest.mark.parametrize(
        "cell, expected",
        [
            ("#1234", {"#1234"}),
            ("Cert. #1234", {"#1234"}),
            ("Certs. #1234, #1235", {"#1234", "#1235"}),
            ("#1234 and #1235", {"#1234", "#1235"}),
            ("#A1234", {"#A1234"}),
            ("#C123", {"#C123"}),
            ("CAVP Cert. 1234", {"#1234"}),
            ("#01234", {"#1234"}),
            ("# 1234", {"#1234"}),
        ],
    )
    def test_marked_numbers_are_found_anywhere_in_a_selected_table(self, cell, expected):
        tables = [table((("AES", cell),), header=(("Algorithm", "Notes"),))]

        assert extract_algorithms_from_tables(tables).algorithms == expected

    @pytest.mark.parametrize(
        "cell, expected",
        [
            ("1234", {"#1234"}),
            ("1234, 1235", {"#1234", "#1235"}),
            ("A1234", {"#A1234"}),
        ],
    )
    def test_bare_numbers_are_found_in_a_certificate_column(self, cell, expected):
        tables = [table((("AES", cell),), header=ALG_HEADER)]

        assert extract_algorithms_from_tables(tables).algorithms == expected

    @pytest.mark.parametrize("cell", ["128", "1234, 1235"])
    def test_bare_numbers_are_ignored_outside_a_certificate_column(self, cell):
        tables = [table((("AES", cell),), header=(("Algorithm", "Key size"),))]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    @pytest.mark.parametrize("cell", ["AES-128", "Vendor Affirmed", "SP 800-90A", "N/A", ""])
    def test_cells_that_are_not_purely_numbers_yield_nothing(self, cell):
        tables = [table((("AES", cell),), header=ALG_HEADER)]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    def test_prefixed_cavp_numbers_survive_surrounding_text(self):
        """
        Calibrated against the policy corpus: a "CAVP Cert" cell routinely lists several numbers alongside
        labels, and the prefixed form stays unambiguous where a bare number would not.
        """
        tables = [
            table(
                (("Version 3.3: A3045, A3053 Version 3.4: A3090", "AES", "CBC"),),
                header=(("CAVP Cert", "Algorithm and Standard", "Mode / Method"),),
            )
        ]

        result = extract_algorithms_from_tables(tables)

        # The version numbers must not come along.
        assert result.algorithms == {"#A3045", "#A3053", "#A3090"}

    def test_prefixed_numbers_are_still_confined_to_certificate_columns(self):
        tables = [table((("AES", "Curve P-256, mode A1234"),), header=(("Algorithm", "Key size"),))]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    def test_unprefixed_numbers_still_need_a_numbers_only_cell(self):
        """Relaxing the cell guard applies to the prefixed form only."""
        tables = [table((("AES", "Version 3.3: 3045"),), header=ALG_HEADER)]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    def test_row_counter_columns_are_not_certificate_columns(self):
        """
        Calibrated against the policy corpus: a column headed only "#" is a row counter in operational
        environment and port tables, never a list of certificate numbers.
        """
        tables = [
            table(
                (("1", "ArubaOS 8.10", "7020 Mobility Controller"), ("2", "ArubaOS 8.10", "7205 Mobility Controller")),
                header=(("#", "Operating System", "Hardware Platform"),),
                caption="Table 4 Tested Operational Environments",
            )
        ]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    def test_ssp_table_is_selected_by_its_certificate_column(self):
        """
        The FIPS 140-3 key/SSP tables carry their numbers in a "Security Function and Cert. Number" column
        while their caption says nothing about algorithms.
        """
        tables = [
            table(
                (
                    ("1", "DRBG Key - CSP", "SP800-90A Rev1 CTR_DRBG"),
                    ("11", "RSA Private Key - CSP", "RSA Private Key Cert. #A2690"),
                ),
                header=(("#", "Key / SSP Name / Type", "Security Function and Cert. Number"),),
                caption="Table 15 SSPs/Keys Used in the Module",
            )
        ]

        result = extract_algorithms_from_tables(tables)

        # The row counters in the "#" column must not come along.
        assert result.algorithms == {"#A2690"}

    def test_split_certificate_column_header_still_selects(self):
        """Layout recognition often splits words apart, e.g. "Securit y Functi on and Cert. Numb er"."""
        tables = [
            table(
                (("RSA Private Key", "RSA Cert. #A2690"),),
                header=(("Key/SSP Name/ Type", "Securit y Functi on and Cert. Numb er"),),
            )
        ]

        result = extract_algorithms_from_tables(tables)

        assert result.algorithms == {"#A2690"}
        assert [hit.selected_by for hit in result.hits] == ["cert_column"]

    def test_certificate_column_in_a_later_header_row_is_used(self):
        """
        A spanning header cell arrives replicated across the columns it covers, so the certificate column
        is announced on the second header row. Indexing the flattened header missed those entirely.
        """
        tables = [
            table(
                (("C1253", "AES", "FIPS 197"), ("4748", "SHA", "FIPS 180-4")),
                header=(
                    ("OpenSSL Module", "OpenSSL Module", "OpenSSL Module"),
                    ("CAVP Certificate #", "Algorithm", "Standard"),
                ),
                caption="Table 10 - CAVP Certificates",
            )
        ]

        assert extract_algorithms_from_tables(tables).algorithms == {"#C1253", "#4748"}

    def test_a_column_spanning_certificate_header_marks_every_column_it_covers(self):
        tables = [
            table(
                (("AES", "A101", "A102"),),
                header=(("Algorithm", "Cert. Number", "Cert. Number"),),
            )
        ]

        assert extract_algorithms_from_tables(tables).algorithms == {"#A101", "#A102"}

    def test_numbers_too_low_to_be_a_certificate_are_dropped(self):
        """`PKCS #1`, self-test numbering and footnote markers are pervasive and indistinguishable."""
        tables = [
            table(
                (("RSA (FIPS186-4) (PKCS #1 v1.5)", "Signature generation"), ("SHA self test #2", "-")),
                header=(("Algorithm", "Certificate Number"),),
            )
        ]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    def test_a_continuation_must_follow_the_table_it_continues(self):
        header = (("Function", "Reference"),)
        tables = [
            table((("SHA", "Cert. #1235"),), header=header, pages=(3,)),
            table((("AES", "Cert. #1234"),), header=header, caption="Table 4: Approved Algorithms", pages=(4,)),
        ]

        result = extract_algorithms_from_tables(tables)

        # The page-3 table merely shares a header shape; it precedes the captioned one.
        assert result.algorithms == {"#1234"}
        assert [hit.selected_by for hit in result.hits] == ["caption"]

    def test_date_columns_are_not_certificate_columns(self):
        """A 'Validation Date' header matches the certificate-column pattern but must be excluded."""
        tables = [table((("AES", "2018-03-23"),), header=(("Algorithm", "Validation Date"),))]

        assert extract_algorithms_from_tables(tables).algorithms == set()

    def test_numbers_are_deduplicated_across_tables(self):
        tables = [
            table((("AES", "#1234"),), header=ALG_HEADER, pages=(4,)),
            table((("AES", "# 01234"),), header=ALG_HEADER, pages=(5,)),
        ]

        assert extract_algorithms_from_tables(tables).algorithms == {"#1234"}

    def test_extracted_ids_carry_the_hash_pruning_relies_on(self):
        """`FIPSCertificate.Heuristics.algorithm_numbers` drops anything without a '#'."""
        tables = [table((("AES", "1234"),), header=ALG_HEADER)]

        assert extract_algorithms_from_tables(tables).algorithms == {"#1234"}


class TestRobustness:
    def test_no_tables(self):
        result = extract_algorithms_from_tables([])

        assert result.algorithms == set()
        assert result.n_tables == 0
        assert not result.used_fallback

    def test_ragged_rows_do_not_crash(self):
        tables = [table((("AES", "#1234"), ("SHA",), ("RSA", "#1235", "extra")), header=ALG_HEADER)]

        assert extract_algorithms_from_tables(tables).algorithms == {"#1234", "#1235"}

    def test_hits_record_provenance(self):
        tables = [table((("AES", "#1234"),), header=ALG_HEADER, caption="Table 4: Approved Algorithms", pages=(4, 5))]

        (hit,) = extract_algorithms_from_tables(tables).hits

        assert hit.caption == "Table 4: Approved Algorithms"
        assert hit.pages == (4, 5)
        assert hit.algorithms == frozenset({"#1234"})

    def test_tables_without_matches_are_not_recorded_as_hits(self):
        tables = [table((("AES", "CBC"),), header=ALG_HEADER)]

        result = extract_algorithms_from_tables(tables)

        assert result.hits == []
        assert result.n_tables == 1


class TestHelpers:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("  Approved   Algorithms  ", "Approved Algorithms"),
            ("Cert. #", "Cert. #"),
            ("Al­gorithm", "Algorithm"),
            ("Cert.​#", "Cert.#"),
        ],
    )
    def test_normalize(self, raw, expected):
        assert normalize(raw) == expected

    @pytest.mark.parametrize(
        "prefix, number, expected",
        [(None, "1234", "#1234"), ("a", "1234", "#A1234"), ("C", "0123", "#C123"), (None, "007", "#7")],
    )
    def test_canonical_id(self, prefix, number, expected):
        assert canonical_id(prefix, number) == expected


def load_projection(name: str) -> list[DocumentTable]:
    """Load a committed projection of a real policy's tables."""
    with as_file(files(tests.data.fips.tables) / name) as path, path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return [
        DocumentTable(
            rows=tuple(tuple(row) for row in entry["rows"]),
            header=tuple(tuple(row) for row in entry["header"]),
            caption=entry["caption"],
            pages=tuple(entry["pages"]),
            is_index=entry["is_index"],
            n_fragments=entry["n_fragments"],
        )
        for entry in raw
    ]


@pytest.fixture(scope="module")
def golden_tables() -> list[DocumentTable]:
    return load_projection(f"{GOLDEN_DGST}_tables.json")


class TestGoldenPolicy:
    """
    Extraction over the tables of a real security policy.

    `<dgst>_tables.json` is a backend-neutral projection of `<dgst>.docling.json`, so the expectations below
    run in ordinary CI without docling installed. Regenerate both with:

        tables = DoclingView(path_to_docling_json).get_tables(include_index=True)
        json.dump([{"caption": t.caption, "pages": list(t.pages), "header": [list(r) for r in t.header],
                    "rows": [list(r) for r in t.rows], "is_index": t.is_index,
                    "n_fragments": t.n_fragments} for t in golden_tables], handle, indent=1, ensure_ascii=False)
    """

    def test_algorithms(self, golden_tables):
        """The certificate numbers of the "Approved Cryptographic Functions" table, and nothing else."""
        result = extract_algorithms_from_tables(golden_tables)

        assert result.algorithms == {"#A1289", "#A4801", "#C2155", "#C2156"}
        assert not result.used_fallback

    def test_only_the_approved_functions_table_contributes(self, golden_tables):
        result = extract_algorithms_from_tables(golden_tables)

        assert [(hit.caption, hit.selected_by) for hit in result.hits] == [
            ("Table 2.1: Approved Cryptographic Functions.", "caption")
        ]

    def test_the_index_table_is_excluded_from_candidates(self, golden_tables):
        assert sum(table.is_index for table in golden_tables) == 1
        assert extract_algorithms_from_tables(golden_tables).n_tables == len(golden_tables) - 1

    def test_the_approved_functions_table_was_stitched_across_pages(self, golden_tables):
        (approved,) = [t for t in golden_tables if t.caption and t.caption.startswith("Table 2.1")]

        assert approved.n_fragments == 2
        assert approved.pages == (5, 6)

    @pytest.mark.skipif(not has_docling, reason="docling is not installed")
    @pytest.mark.docling
    def test_docling_view_reproduces_the_projection(self, golden_tables):
        """Guards the projection against drift when docling changes how it recovers tables."""
        from sec_certs.document.docling import DoclingView

        with as_file(files(tests.data.fips.tables) / f"{GOLDEN_DGST}.docling.json") as path:
            actual = DoclingView(path).get_tables(include_index=True)

        assert [(t.caption, t.pages, t.header, t.rows, t.is_index, t.n_fragments) for t in actual] == [
            (t.caption, t.pages, t.header, t.rows, t.is_index, t.n_fragments) for t in golden_tables
        ]
