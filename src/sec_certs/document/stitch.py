from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, replace

from sec_certs.document.base import DocumentTable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PageSpan:
    """
    Vertical extent of an item on a single page, normalized to a top-left origin.

    `top` and `bottom` are fractions of the page height: 0.0 is the top edge, 1.0 the bottom edge.
    """

    page: int
    top: float
    bottom: float


@dataclass(frozen=True)
class TableFragment:
    """A table as the backend reported it, before page fragments are merged."""

    table: DocumentTable
    span: PageSpan | None = None
    """Where the fragment starts, i.e. its extent on its first page. None without provenance."""

    last_span: PageSpan | None = None
    """Where the fragment ends, i.e. its extent on its last page. Defaults to `span`."""

    @property
    def end(self) -> PageSpan | None:
        return self.last_span or self.span


@dataclass(frozen=True)
class StitchParams:
    top_margin: float = 0.20
    """A continuation must start within this fraction of the top of its page."""

    bottom_margin: float = 0.80
    """
    The fragment being continued must reach at least this far down its page.

    Calibrated against the FIPS security policy corpus using continuations proven by row-counter
    continuity: 0.80 recovers 92% of them where 0.85 recovered 84%, and sits just below their 10th
    percentile. Raise it if false merges ever show up; the corpus offered too few provable
    non-continuations to measure that side.
    """

    top_furniture_zone: float = 0.06
    bottom_furniture_zone: float = 0.90
    """
    Bands at the top and bottom of a page holding running headers and footers.

    Content there never separates two fragments of the same table. This is geometric on purpose: the
    backend labels running footers and header logos as ordinary body text and pictures, so no label
    filter can recognize them.
    """

    require_equal_columns: bool = True
    """Whether fragments must agree on column count to be merged."""

    use_blockers: bool = True
    """
    Whether intervening content in the vertical gap between two fragments prevents a merge.

    Guards the case the margin tests cannot catch: two unrelated, uncaptioned tables with the same column
    count, one ending flush at the bottom of a page and the next starting flush at the top of the
    following one. Only content outside the furniture zones counts, since a running footer sits in the gap
    on every page.
    """


def stitch_fragments(
    fragments: Sequence[TableFragment],
    blockers: Sequence[PageSpan] = (),
    params: StitchParams | None = None,
) -> list[DocumentTable]:
    """
    Merge page fragments of the same table into single tables.

    :param fragments: fragments in reading order.
    :param blockers: spans of other content in the document, used to detect that something sits between
        two fragments and they therefore cannot be the same table.
    :param params: thresholds and switches of the merge rule.
    :return: logical tables, in reading order.
    """
    params = params or StitchParams()
    groups: list[list[TableFragment]] = []

    for fragment in fragments:
        if groups and _continues(groups[-1][-1], fragment, blockers, params):
            groups[-1].append(fragment)
        else:
            groups.append([fragment])

    return [_merge(group) for group in groups]


def _continues(prev: TableFragment, nxt: TableFragment, blockers: Sequence[PageSpan], params: StitchParams) -> bool:
    if nxt.table.caption is not None:
        return False  # a caption of its own starts a new table
    if nxt.table.is_index != prev.table.is_index or nxt.table.layer is not prev.table.layer:
        return False
    if prev.table.n_cols == 0:
        return False
    if params.require_equal_columns and nxt.table.n_cols != prev.table.n_cols:
        return False
    # A head is judged by where it ends, a tail by where it starts.
    head, tail = prev.end, nxt.span
    if head is None or tail is None:
        logger.debug("Table fragment without provenance, not stitching it.")
        return False
    if tail.page != head.page + 1:
        return False
    if head.bottom < params.bottom_margin or tail.top > params.top_margin:
        return False
    return not (params.use_blockers and _blocked(head, tail, blockers, params))


def _blocked(head: PageSpan, tail: PageSpan, blockers: Sequence[PageSpan], params: StitchParams) -> bool:
    """Whether any content sits below the head on its page, or above the tail on its page."""
    return any(
        (blocker.page == head.page and blocker.top > head.bottom)
        or (blocker.page == tail.page and blocker.bottom < tail.top)
        for blocker in blockers
        if not _is_page_furniture(blocker, params)
    )


def _is_page_furniture(span: PageSpan, params: StitchParams) -> bool:
    """Whether a span sits in the band a running header or footer occupies on every page."""
    return span.bottom <= params.top_furniture_zone or span.top >= params.bottom_furniture_zone


def _merge(group: list[TableFragment]) -> DocumentTable:
    head = group[0].table
    if len(group) == 1:
        return head

    header = head.header
    rows = list(head.rows)
    pages = set(head.pages)

    for fragment in group[1:]:
        continuation = fragment.table
        promoted, repeated = _classify_header(header, continuation.header)
        if promoted:
            header = continuation.header
        elif not repeated:
            # The backend called these header rows, but they match no header we know of, so they are data.
            rows.extend(continuation.header)
        rows.extend(_body_without_repeated_header(continuation, header))
        pages |= set(continuation.pages)

    # Fragments may disagree on width when `require_equal_columns` is off, and a DocumentTable promises
    # rectangular rows.
    width = max((len(row) for row in (*header, *rows)), default=0)
    return replace(
        head,
        header=tuple(_padded(row, width) for row in header),
        rows=tuple(_padded(row, width) for row in rows),
        pages=tuple(sorted(pages)),
        n_fragments=len(group),
    )


def _padded(row: tuple[str, ...], width: int) -> tuple[str, ...]:
    return row if len(row) == width else row + ("",) * (width - len(row))


def _classify_header(
    header: tuple[tuple[str, ...], ...], continuation_header: tuple[tuple[str, ...], ...]
) -> tuple[bool, bool]:
    """
    What a continuation's own header rows are, relative to the header established so far.

    :return: whether they should become the header of the merged table, and whether they merely repeat it.
    """
    if not continuation_header:
        return False, True
    if not header:
        return True, False  # the backend only recognized the header on a later page
    return False, _normalized(continuation_header) == _normalized(header)


def _body_without_repeated_header(
    fragment: DocumentTable, header: tuple[tuple[str, ...], ...]
) -> tuple[tuple[str, ...], ...]:
    """
    Body rows of a continuation, with the header the document repeats on each page removed.

    The repeat lands in the body rows when the backend did not recognize it as a header; when it did,
    `_classify_header` has already dealt with it.
    """
    if not header:
        return fragment.rows
    if _normalized(fragment.rows[: len(header)]) == _normalized(header):
        return fragment.rows[len(header) :]
    return fragment.rows


def _normalized(block: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(cell.strip().casefold() for cell in row) for row in block)
