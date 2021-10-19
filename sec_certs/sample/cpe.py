from dataclasses import dataclass
from typing import ClassVar, List, Optional

from sec_certs.serialization import ComplexSerializableType


@dataclass(init=False)
class CPE(ComplexSerializableType):
    uri: str
    title: str
    version: str
    vendor: str
    item_name: str
    pandas_columns: ClassVar[List[str]] = ['uri', 'vendor', 'item_name', 'version', 'title']

    def __init__(self, uri: Optional[str] = None, title: Optional[str] = None):
        self.uri = uri
        self.title = title

        if self.uri:
            self.vendor = ' '.join(self.uri.split(':')[3].split('_'))
            self.item_name = ' '.join(self.uri.split(':')[4].split('_'))
            self.version = self.uri.split(':')[5]

    def __lt__(self, other: 'CPE'):
        return self.title < other.title

    @property
    def serialized_attributes(self) -> List[str]:
        return ['uri', 'title']

    @property
    def pandas_tuple(self):
        return self.uri, self.vendor, self.item_name, self.version, self.title

    def __hash__(self):
        return hash(self.uri)

    def __eq__(self, other):
        if not isinstance(other, CPE):
            return False
        return self.uri == other.uri