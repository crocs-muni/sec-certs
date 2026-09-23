"""
Tests of parsing security policies that follow the BR1 template.

They build `DocumentBlock` sequences directly, so the chapter and table logic is covered without docling
installed or a converted policy on disk. The headings come from the BR1 template itself.
"""

from __future__ import annotations

import json

from sec_certs.configuration import config
from sec_certs.document.base import BlockKind, DocumentBlock, DocumentTable
from sec_certs.heuristics.br1.chapter_parsing.chapter_utils import chapters_from_json
from sec_certs.heuristics.br1.chapter_parsing.mapper import extract_chapters
from sec_certs.heuristics.br1.chapter_parsing.validator import validate_chapters
from sec_certs.heuristics.br1.table_parsing.model.br1_tables import BR1Tables
from sec_certs.heuristics.br1.table_parsing.model.entry_types.algorithms import ApprovedAlgo
from sec_certs.heuristics.br1.table_parsing.parser import parse_tables
from sec_certs.serialization.json import CustomJSONDecoder, CustomJSONEncoder

ALGORITHMS = (2, 5)
APPROVED_HEADER = ("Algorithm", "CAVP Cert", "Properties", "Reference")
AES = ("AES-GCM", "A1234", "Key Length: 128, 256", "SP 800-38D")
HMAC = ("HMAC-SHA2-256", "A1234", "Key Length: 112-524288", "FIPS 198-1")


def text(line: str) -> DocumentBlock:
    return DocumentBlock(BlockKind.TEXT, line)


def table(header: tuple[str, ...], *rows: tuple[str, ...]) -> DocumentBlock:
    rendered = "\n".join("| " + " | ".join(row) + " |" for row in (header, *rows))
    return DocumentBlock(BlockKind.TABLE, rendered, DocumentTable(header=(header,), rows=rows))


def policy(
    sections: dict[tuple[int, int], list[DocumentBlock]] | None = None,
    missing_chapters: set[int] | None = None,
    as_text: set[tuple[int, int]] | None = None,
) -> list[DocumentBlock]:
    """
    Blocks of a policy with every chapter of the template, each with a line of text.

    :param sections: blocks appended to the (chapter, subchapter) numbered from 1.
    :param missing_chapters: chapters left out with all their subchapters.
    :param as_text: headings the converter recognized as plain text rather than as headings.
    """
    sections, missing_chapters, as_text = sections or {}, missing_chapters or set(), as_text or set()
    blocks = []
    for i, chapter in enumerate(chapters_from_json(), 1):
        if i in missing_chapters:
            continue
        blocks += [DocumentBlock(BlockKind.HEADING, f"{i} {chapter.title}"), text("About the chapter.")]
        for j, subchapter in enumerate(chapter.subchapters, 1):
            kind = BlockKind.TEXT if (i, j) in as_text else BlockKind.HEADING
            blocks += [DocumentBlock(kind, f"{i}.{j} {subchapter.title}"), text("About the subchapter.")]
            blocks += sections.get((i, j), [])
    return blocks


def deviations(blocks: list[DocumentBlock]) -> int:
    errors, _ = validate_chapters(extract_chapters(blocks))
    return errors


class TestChapters:
    def test_policy_with_every_chapter_has_no_deviation(self):
        assert deviations(policy()) == 0

    def test_missing_chapters_are_deviations(self):
        assert deviations(policy(missing_chapters={1, 2, 3, 4, 5, 6})) > config.br1_error_accept

    def test_numbered_heading_recognized_as_text_still_starts_a_subchapter(self):
        chapters = extract_chapters(policy(as_text={(2, 3)}))

        assert chapters[1].subchapters[2].found

    def test_heading_text_is_not_a_part_of_the_content(self):
        chapters = extract_chapters(policy())

        assert chapters[1].subchapters[4].content.strip() == "About the subchapter."


class TestTables:
    def test_rows_are_mapped_to_fields_by_the_header(self):
        tables = parse_tables(
            extract_chapters(policy({ALGORITHMS: [text("Approved Algorithms"), table(APPROVED_HEADER, AES)]}))
        )

        assert tables.approved_algorithms.found
        assert tables.approved_algorithms.entries == [
            ApprovedAlgo(algorithm=AES[0], cavpCertName=AES[1], properties=AES[2], reference=AES[3])
        ]

    def test_columns_are_found_in_any_order_and_despite_split_words(self):
        header = ("Reference", "Propert ies", "Algorithm", "CAVP Cert")
        row = (AES[3], AES[2], AES[0], AES[1])
        tables = parse_tables(extract_chapters(policy({ALGORITHMS: [text("Approved Algorithms"), table(header, row)]})))

        assert tables.approved_algorithms.entries == [
            ApprovedAlgo(algorithm=AES[0], cavpCertName=AES[1], properties=AES[2], reference=AES[3])
        ]

    def test_table_continued_on_the_next_page_is_joined_without_its_repeated_header(self):
        blocks = [text("Approved Algorithms"), table(APPROVED_HEADER, AES), table(APPROVED_HEADER, HMAC)]
        tables = parse_tables(extract_chapters(policy({ALGORITHMS: blocks})))

        assert [entry.algorithm for entry in tables.approved_algorithms.entries] == [AES[0], HMAC[0]]

    def test_table_with_other_columns_than_the_template_is_rejected(self):
        header = ("Algorithm Name", "CAVP Cert", "Properties", "Reference")
        tables = parse_tables(extract_chapters(policy({ALGORITHMS: [text("Approved Algorithms"), table(header, AES)]})))

        assert not tables.approved_algorithms.found
        assert tables.approved_algorithms.entries == []

    def test_table_with_an_extra_column_is_rejected(self):
        header = (*APPROVED_HEADER, "Notes")
        tables = parse_tables(
            extract_chapters(policy({ALGORITHMS: [text("Approved Algorithms"), table(header, (*AES, "-"))]}))
        )

        assert not tables.approved_algorithms.found

    def test_tables_sharing_a_subchapter_are_split_by_their_titles(self):
        blocks = [
            text("Approved Algorithms"),
            table(APPROVED_HEADER, AES),
            text("Non-Approved, Not Allowed Algorithms"),
            table(("Name", "Use and Function"), ("MD5", "Hashing")),
        ]
        tables = parse_tables(extract_chapters(policy({ALGORITHMS: blocks})))

        assert [entry.algorithm for entry in tables.approved_algorithms.entries] == [AES[0]]
        assert [(entry.name, entry.use) for entry in tables.non_approved_not_allowed.entries] == [("MD5", "Hashing")]

    def test_table_without_its_title_is_not_found(self):
        tables = parse_tables(extract_chapters(policy({ALGORITHMS: [table(APPROVED_HEADER, AES)]})))

        assert not tables.approved_algorithms.found

    def test_table_of_a_subchapter_with_a_single_table_needs_no_title(self):
        header = ("Physical Port", "Logical Interface(s)", "Data That Passes")
        tables = parse_tables(extract_chapters(policy({(3, 1): [table(header, ("USB", "Data Input", "Commands"))]})))

        assert [entry.physicalPort for entry in tables.ports_interfaces.entries] == ["USB"]


def test_tables_survive_a_round_trip_through_json():
    tables = BR1Tables()
    tables.approved_algorithms.found = True
    tables.approved_algorithms.entries = [
        ApprovedAlgo(algorithm=AES[0], cavpCertName=AES[1], properties=AES[2], reference=AES[3])
    ]

    assert json.loads(json.dumps(tables, cls=CustomJSONEncoder), cls=CustomJSONDecoder) == tables
