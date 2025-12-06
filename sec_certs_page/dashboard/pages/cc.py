"""Common Criteria (CC) collection dashboard page."""

import dash
from dash import html

from ..pages.common import create_collection_page_layout
from ..types.common import CollectionType

COLLECTION = CollectionType.CommonCriteria


def layout(**kwargs) -> html.Div:
    """Layout for the CC collection dashboard page."""
    return create_collection_page_layout(
        collection_type=COLLECTION,
        title="Common Criteria Dashboard",
    )


dash.register_page(
    __name__,
    path="/cc",
    title="Common Criteria Dashboard",
    name="Common Criteria Dashboard",
    layout=layout,
)
