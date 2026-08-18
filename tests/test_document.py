from __future__ import annotations

import pytest

import sec_certs.configuration as config_module
from sec_certs.converter import has_docling
from sec_certs.document.base import DocumentLayer, DocumentTable, TablesNotSupportedError
from sec_certs.document.plaintext import PlainTextView

if has_docling:
    from sec_certs.document.docling import DoclingView
from sec_certs.document.stitch import PageSpan, StitchParams, TableFragment, stitch_fragments
from sec_certs.document.utils import get_view_cls

HEADER = (("Algorithm", "Cert. #"),)


def fragment(
    page: int,
    rows: tuple[tuple[str, ...], ...],
    *,
    header: tuple[tuple[str, ...], ...] = HEADER,
    caption: str | None = None,
    top: float | None = None,
    bottom: float | None = None,
    is_index: bool = False,
    layer: DocumentLayer = DocumentLayer.BODY,
    with_span: bool = True,
) -> TableFragment:
    """A fragment that by default sits flush at the bottom of its page, i.e. looks continuable."""
    table = DocumentTable(
        rows=rows,
        header=header,
        caption=caption,
        pages=(page,),
        is_index=is_index,
        layer=layer,
    )
    span = PageSpan(page=page, top=0.5 if top is None else top, bottom=0.9 if bottom is None else bottom)
    return TableFragment(table=table, span=span if with_span else None)


def continuation(page: int, rows: tuple[tuple[str, ...], ...], **kwargs) -> TableFragment:
    """A fragment that by default sits flush at the top of its page, i.e. looks like a continuation."""
    kwargs.setdefault("top", 0.1)
    kwargs.setdefault("bottom", 0.5)
    return fragment(page, rows, **kwargs)


class TestStitching:
    def test_flush_fragments_on_consecutive_pages_merge(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),))

        (table,) = stitch_fragments([head, tail])

        assert table.n_fragments == 2
        assert table.pages == (4, 5)
        assert table.rows == (("AES", "#1"), ("SHA", "#2"))
        assert table.header == HEADER

    def test_single_fragment_is_returned_unchanged(self):
        head = fragment(4, (("AES", "#1"),))

        assert stitch_fragments([head]) == [head.table]

    def test_own_caption_starts_a_new_table(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),), caption="Table 5: Something else")

        assert len(stitch_fragments([head, tail])) == 2

    def test_pages_must_be_consecutive(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(6, (("SHA", "#2"),))

        assert len(stitch_fragments([head, tail])) == 2

    def test_same_page_fragments_do_not_merge(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(4, (("SHA", "#2"),))

        assert len(stitch_fragments([head, tail])) == 2

    def test_column_count_must_match_by_default(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2", "extra"),), header=(("Algorithm", "Cert. #", "Mode"),))

        assert len(stitch_fragments([head, tail])) == 2
        assert len(stitch_fragments([head, tail], params=StitchParams(require_equal_columns=False))) == 1

    def test_head_not_reaching_page_bottom_does_not_continue(self):
        head = fragment(4, (("AES", "#1"),), bottom=0.5)
        tail = continuation(5, (("SHA", "#2"),))

        assert len(stitch_fragments([head, tail])) == 2

    def test_tail_not_starting_at_page_top_is_not_a_continuation(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),), top=0.4)

        assert len(stitch_fragments([head, tail])) == 2

    def test_content_in_the_gap_below_the_head_prevents_the_merge(self):
        head = fragment(4, (("AES", "#1"),), bottom=0.82)
        tail = continuation(5, (("SHA", "#2"),))
        below_head = PageSpan(page=4, top=0.85, bottom=0.88)

        assert len(stitch_fragments([head, tail], blockers=[below_head])) == 2
        assert len(stitch_fragments([head, tail], blockers=[below_head], params=StitchParams(use_blockers=False))) == 1

    def test_content_in_the_gap_above_the_tail_prevents_the_merge(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),), top=0.10)
        above_tail = PageSpan(page=5, top=0.07, bottom=0.09)

        assert len(stitch_fragments([head, tail], blockers=[above_tail])) == 2

    def test_a_running_footer_does_not_prevent_the_merge(self):
        """
        The backend labels running footers as ordinary body text, so they reach the blocker list and sit in
        the gap on every page. Treating them as content split 39% of the policy corpus' tables.
        """
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),))
        footer = PageSpan(page=4, top=0.909, bottom=0.919)

        assert len(stitch_fragments([head, tail], blockers=[footer])) == 1

    def test_a_header_logo_does_not_prevent_the_merge(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),))
        logo = PageSpan(page=5, top=0.004, bottom=0.026)

        assert len(stitch_fragments([head, tail], blockers=[logo])) == 1

    def test_content_outside_the_gap_allows_the_merge(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),))
        blockers = [
            PageSpan(page=4, top=0.2, bottom=0.4),  # above the head, not between them
            PageSpan(page=5, top=0.7, bottom=0.8),  # below the tail, not between them
            PageSpan(page=9, top=0.0, bottom=1.0),  # unrelated page
        ]

        assert len(stitch_fragments([head, tail], blockers=blockers)) == 1

    def test_three_fragment_chain_merges_into_one(self):
        fragments = [
            fragment(4, (("AES", "#1"),)),
            continuation(5, (("SHA", "#2"),), top=0.1, bottom=0.9),
            continuation(6, (("RSA", "#3"),)),
        ]

        (table,) = stitch_fragments(fragments)

        assert table.n_fragments == 3
        assert table.pages == (4, 5, 6)
        assert table.rows == (("AES", "#1"), ("SHA", "#2"), ("RSA", "#3"))

    def test_broken_middle_fragment_splits_the_chain(self):
        fragments = [
            fragment(4, (("AES", "#1"),)),
            continuation(5, (("SHA", "#2"),), caption="Table 5: Interrupting caption", bottom=0.9),
            continuation(6, (("RSA", "#3"),)),
        ]

        tables = stitch_fragments(fragments)

        assert [table.n_fragments for table in tables] == [1, 2]

    def test_fragment_without_provenance_is_not_stitched(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),), with_span=False)

        assert len(stitch_fragments([head, tail])) == 2

    def test_index_and_data_tables_do_not_merge(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),), is_index=True)

        assert len(stitch_fragments([head, tail])) == 2

    def test_layers_must_match(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2"),), layer=DocumentLayer.FURNITURE)

        assert len(stitch_fragments([head, tail])) == 2

    def test_header_repeated_as_body_rows_is_stripped(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("Algorithm", "Cert. #"), ("SHA", "#2")), header=())

        (table,) = stitch_fragments([head, tail], params=StitchParams(require_equal_columns=False))

        assert table.rows == (("AES", "#1"), ("SHA", "#2"))

    def test_header_repeated_with_different_case_is_stripped(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, ((" algorithm ", "CERT. #"), ("SHA", "#2")), header=())

        (table,) = stitch_fragments([head, tail], params=StitchParams(require_equal_columns=False))

        assert table.rows == (("AES", "#1"), ("SHA", "#2"))

    def test_body_row_resembling_no_header_is_kept(self):
        head = fragment(4, (("AES", "#1"),), header=())
        tail = continuation(5, (("SHA", "#2"),), header=())

        (table,) = stitch_fragments([head, tail])

        assert table.rows == (("AES", "#1"), ("SHA", "#2"))

    def test_head_reaching_just_past_the_bottom_margin_continues(self):
        head = fragment(4, (("AES", "#1"),), bottom=0.81)
        tail = continuation(5, (("SHA", "#2"),))

        assert len(stitch_fragments([head, tail])) == 1

    def test_head_stopping_just_short_of_the_bottom_margin_does_not(self):
        head = fragment(4, (("AES", "#1"),), bottom=0.79)
        tail = continuation(5, (("SHA", "#2"),))

        assert len(stitch_fragments([head, tail])) == 2

    def test_a_continuations_own_header_rows_are_kept_when_they_are_not_a_repeat(self):
        """The backend sometimes classifies a data row as a header; that row is still data."""
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#3"),), header=(("3DES", "#2"),))

        (table,) = stitch_fragments([head, tail])

        assert table.rows == (("AES", "#1"), ("3DES", "#2"), ("SHA", "#3"))
        assert table.header == HEADER

    def test_a_continuations_header_is_promoted_when_the_head_has_none(self):
        head = fragment(4, (("AES", "#1"),), header=())
        tail = continuation(5, (("SHA", "#2"),))

        (table,) = stitch_fragments([head, tail])

        assert table.header == HEADER
        assert table.rows == (("AES", "#1"), ("SHA", "#2"))

    def test_a_head_is_judged_by_where_it_ends_not_where_it_starts(self):
        """A fragment reported across two pages must be continued from its last page."""
        head = TableFragment(
            DocumentTable(rows=(("AES", "#1"),), header=HEADER, pages=(4, 5)),
            span=PageSpan(page=4, top=0.3, bottom=0.99),
            last_span=PageSpan(page=5, top=0.05, bottom=0.9),
        )
        tail = continuation(6, (("SHA", "#2"),))

        (table,) = stitch_fragments([head, tail])

        assert table.n_fragments == 2
        assert table.pages == (4, 5, 6)

    def test_merged_rows_stay_rectangular_when_widths_disagree(self):
        head = fragment(4, (("AES", "#1"),))
        tail = continuation(5, (("SHA", "#2", "extra"),), header=(("Algorithm", "Cert. #", "Mode"),))

        (table,) = stitch_fragments([head, tail], params=StitchParams(require_equal_columns=False))

        assert {len(row) for row in table.rows} == {table.n_cols}
        assert table.to_dataframe().shape == (len(table.rows), table.n_cols)

    def test_empty_input(self):
        assert stitch_fragments([]) == []


def row_content(row: tuple[str, ...]) -> tuple[str, ...]:
    """A row reduced to the content that must survive any transformation."""
    return tuple(cell.strip().casefold() for cell in row if cell.strip())


def distinct_content(tables: list[DocumentTable]) -> set[tuple[str, ...]]:
    return {row_content(row) for t in tables for row in (*t.header, *t.rows) if row_content(row)}


class TestStitchingContracts:
    """
    Invariants that must hold for every input, rather than examples of particular inputs.

    Each of these would have caught a defect that shipped past the example-based tests above.
    """

    @pytest.mark.parametrize("head_header", [(), HEADER], ids=["headless-head", "headed-head"])
    @pytest.mark.parametrize(
        "tail_header",
        [(), HEADER, (("3DES", "#9"),), (("ALGORITHM", " cert. # "),)],
        ids=["none", "exact-repeat", "not-a-repeat", "repeat-modulo-case"],
    )
    @pytest.mark.parametrize("n", [2, 3], ids=["two-fragments", "three-fragments"])
    def test_stitching_never_loses_row_content(self, head_header, tail_header, n):
        """
        Merging may drop a header the document repeats on each page; it may not drop anything else.

        The header-classification defect deleted 9202 non-empty cells across the policy corpus precisely
        because no example test paired a continuation with a header of its own.
        """
        fragments = [fragment(4, (("AES", "#1"),), header=head_header)]
        for i in range(1, n):
            fragments.append(
                continuation(4 + i, ((f"ALG{i}", f"#{100 + i}"),), header=tail_header, top=0.05, bottom=0.9)
            )

        merged = stitch_fragments(fragments)

        lost = distinct_content([f.table for f in fragments]) - distinct_content(merged)
        assert not lost, f"content vanished during merge: {sorted(lost)}"

    @pytest.mark.parametrize("require_equal_columns", [True, False])
    def test_merged_tables_are_rectangular_and_loadable(self, require_equal_columns):
        """
        `DocumentTable.rows` promises equal-length rows, and `to_dataframe` relies on it.

        Ragged output made `to_dataframe()` raise instead of returning a frame.
        """
        fragments = [
            fragment(4, (("AES", "#1"),)),
            continuation(5, (("SHA", "#2", "extra"),), header=(("Algorithm", "Cert. #", "Mode"),)),
            continuation(6, (("RSA",),), header=(("Algorithm",),), top=0.05, bottom=0.9),
        ]

        for table in stitch_fragments(fragments, params=StitchParams(require_equal_columns=require_equal_columns)):
            widths = {len(row) for row in (*table.header, *table.rows)}
            assert len(widths) <= 1, f"ragged table: {widths}"
            assert table.to_dataframe().shape == (len(table.rows), table.n_cols)


class TestViewContracts:
    """Contracts every DocumentView implementation has to satisfy, whoever writes the next one."""

    @pytest.mark.parametrize("view_cls", [PlainTextView, *([DoclingView] if has_docling else [])])
    def test_table_support_flag_matches_actual_behaviour(self, view_cls, tmp_path):
        """
        A view that advertises table support must not refuse, and one that does not must refuse.

        Two separate signals for one capability drift apart silently: a new view could set the flag and
        forget the method, and the batch-level gate would then let it into the worker pool.
        """
        view = view_cls(tmp_path / "artifact")

        if view_cls.supports_tables:
            with pytest.raises(Exception) as excinfo:  # noqa: B017 - the artifact is absent, so it must fail
                view.get_tables()
            assert not isinstance(excinfo.value, TablesNotSupportedError)
        else:
            with pytest.raises(TablesNotSupportedError):
                view.get_tables()


class TestDocumentTable:
    def test_column_names_dot_join_multirow_headers(self):
        table = DocumentTable(header=(("Algorithm", "Cert."), ("", "#")), rows=(("AES", "1"),))

        assert table.column_names() == ["Algorithm", "Cert..#"]

    def test_column_names_pad_ragged_header_rows(self):
        """Truncating would leave a name list shorter than the table is wide."""
        table = DocumentTable(header=(("A", "B", "C"), ("x", "y")), rows=(("1", "2", "3"),))

        assert table.column_names() == ["A.x", "B.y", "C"]
        assert table.to_dataframe().shape == (1, 3)

    def test_column_names_none_without_header(self):
        assert DocumentTable(rows=(("AES", "1"),)).column_names() is None

    def test_empty_table(self):
        table = DocumentTable()

        assert table.is_empty
        assert table.n_cols == 0
        assert table.to_text() == ""

    def test_to_dataframe(self):
        table = DocumentTable(header=HEADER, rows=(("AES", "#1"), ("SHA", "#2")))

        df = table.to_dataframe()

        assert list(df.columns) == ["Algorithm", "Cert. #"]
        assert df.shape == (2, 2)

    def test_to_text(self):
        table = DocumentTable(header=HEADER, rows=(("AES", " #1 "),))

        assert table.to_text() == "Algorithm Cert. #\nAES #1"
        assert table.to_text(include_header=False) == "AES #1"
        assert table.to_text(cell_sep="|") == "Algorithm|Cert. #\nAES|#1"


class TestViewCapabilities:
    def test_plaintext_view_refuses_tables(self, tmp_path):
        view = PlainTextView(tmp_path / "policy.txt")

        with pytest.raises(TablesNotSupportedError):
            view.get_tables()

    def test_get_view_cls_follows_the_configured_converter(self, monkeypatch):
        monkeypatch.setattr(config_module.config, "pdf_converter", "pdftotext")

        assert get_view_cls() is PlainTextView
        assert get_view_cls().supports_tables is False

    def test_get_view_cls_rejects_unknown_converter(self, monkeypatch):
        monkeypatch.setattr(config_module.config, "pdf_converter", "nonsense")

        with pytest.raises(ValueError, match="Unknown PDF converter"):
            get_view_cls()

    @pytest.mark.skipif(not has_docling, reason="docling is not installed")
    @pytest.mark.docling
    def test_docling_view_supports_tables(self, monkeypatch):
        from sec_certs.document.docling import DoclingView

        monkeypatch.setattr(config_module.config, "pdf_converter", "docling")

        assert get_view_cls() is DoclingView
        assert get_view_cls().supports_tables is True
