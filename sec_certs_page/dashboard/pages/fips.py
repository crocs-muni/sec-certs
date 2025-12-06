"""FIPS 140 collection dashboard page."""

import dash
from dash import html

from ..pages.common import create_collection_page_layout
from ..types.common import CollectionType

COLLECTION = CollectionType.FIPS140


def layout(**kwargs) -> html.Div:
    """Layout for the FIPS 140 collection dashboard page."""
    return create_collection_page_layout(
        collection_type=COLLECTION,
        title="FIPS 140 Dashboard",
    )


dash.register_page(
    __name__,
    path="/fips",
    title="FIPS 140 Dashboard",
    name="FIPS 140 Dashboard",
    layout=layout,
)
