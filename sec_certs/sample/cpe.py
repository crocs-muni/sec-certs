from dataclasses import dataclass
from typing import ClassVar, List, Optional, Tuple
from sec_certs.serialization import ComplexSerializableType


@dataclass(init=False)
class CPE(ComplexSerializableType):
    uri: str
    title: str
    version: str
    vendor: str
    item_name: str
    start_version: Optional[Tuple[str, str]]
    end_version: Optional[Tuple[str, str]]

    pandas_columns: ClassVar[List[str]] = ['uri', 'vendor', 'item_name', 'version', 'title', 'start_version', 'end_version']

    def __init__(self, uri: Optional[str] = None,
                 title: Optional[str] = None,
                 start_version: Optional[Tuple[str, str]] = None,
                 end_version: Optional[Tuple[str, str]] = None):
        self.uri = uri
        self.title = title
        self.start_version = tuple(start_version) if start_version else None
        self.end_version = tuple(end_version) if end_version else None

        if self.uri:
            self.vendor = ' '.join(self.uri.split(':')[3].split('_'))
            self.item_name = ' '.join(self.uri.split(':')[4].split('_'))
            self.version = self.uri.split(':')[5]

    def __lt__(self, other: 'CPE'):
        return self.title < other.title

    @property
    def serialized_attributes(self) -> List[str]:
        return ['uri', 'title', 'start_version', 'end_version']

    @property
    def pandas_tuple(self):
        return self.uri, self.vendor, self.item_name, self.version, self.title

    def __hash__(self):
        return hash((self.uri, self.start_version, self.end_version))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.uri == other.uri and self.start_version == other.start_version and self.end_version == other.end_version