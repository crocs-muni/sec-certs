from typing import Protocol

from sec_certs_page.dashboard.types.filter import FilterSpec, FilterUIType


class FilterRegistryInterface(Protocol):
    _filters: dict[str, FilterSpec]
    _initialized: bool

    @classmethod
    def get_filter_definition(cls, filter_id: str) -> FilterSpec | None: ...
    @classmethod
    def get_all_filters(cls) -> dict[str, FilterSpec]: ...
    @classmethod
    def get_filters_by_ui_type(cls, ui_type: FilterUIType) -> list[FilterSpec]: ...
