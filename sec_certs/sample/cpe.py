from dataclasses import dataclass
from functools import lru_cache
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.serialization.pandas import PandasSerializableType


@dataclass(init=False)
class CPE(PandasSerializableType, ComplexSerializableType):
    uri: str
    version: str
    vendor: str
    item_name: str
    title: Optional[str]
    start_version: Optional[Tuple[str, str]]
    end_version: Optional[Tuple[str, str]]

    __slots__ = ["uri", "version", "vendor", "item_name", "title", "start_version", "end_version"]

    pandas_columns: ClassVar[List[str]] = [
        "uri",
        "vendor",
        "item_name",
        "version",
        "title",
        "start_version",
        "end_version",
    ]

    def __init__(
        self,
        uri: str,
        title: Optional[str] = None,
        start_version: Optional[Tuple[str, str]] = None,
        end_version: Optional[Tuple[str, str]] = None,
    ):
        super().__init__()
        self.uri = uri
        self.vendor = " ".join(self.uri.split(":")[3].split("_"))
        self.item_name = " ".join(self.uri.split(":")[4].split("_"))
        self.version = self.uri.split(":")[5]
        self.title = title
        self.start_version = start_version
        self.end_version = end_version

    def __lt__(self, other: "CPE") -> bool:
        return self.uri < other.uri

    @classmethod
    def from_dict(cls, dct: Dict[str, Any]) -> "CPE":
        if isinstance(dct["start_version"], list):
            dct["start_version"] = tuple(dct["start_version"])
        if isinstance(dct["end_version"], list):
            dct["end_version"] = tuple(dct["end_version"])
        return super().from_dict(dct)

    @property
    def serialized_attributes(self) -> List[str]:
        return ["uri", "title", "start_version", "end_version"]

    @property
    def update(self) -> str:
        if self.uri is None:
            raise RuntimeError("URI is missing.")
        return " ".join(self.uri.split(":")[6].split("_"))

    @property
    def target_hw(self) -> str:
        if self.uri is None:
            raise RuntimeError("URI is missing.")
        return " ".join(self.uri.split(":")[11].split("_"))

    @property
    def pandas_tuple(self) -> Tuple:
        return self.uri, self.vendor, self.item_name, self.version, self.title

    def __hash__(self) -> int:
        return hash((self.uri, self.start_version, self.end_version))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.uri == other.uri
            and self.start_version == other.start_version
            and self.end_version == other.end_version
        )


@lru_cache(maxsize=4096)
def cached_cpe(*args, **kwargs):
    return CPE(*args, **kwargs)
