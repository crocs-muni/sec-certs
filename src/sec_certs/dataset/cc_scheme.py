from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

from sec_certs import constants
from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.sample.cc_scheme import CCScheme
from sec_certs.serialization.json import ComplexSerializableType

logger = logging.getLogger()


class CCSchemeDataset(JSONPathDataset, ComplexSerializableType):
    """
    A dataset of data from CC scheme websites.

    Each `.get_*` method returns a list of dict entries from the given scheme.
    The entries do not share many keys, but each one has at least some form
    of a product name and most have a vendor/developer/manufacturer field.
    """

    def __init__(self, schemes: dict[str, CCScheme], json_path: str | Path = constants.DUMMY_NONEXISTING_PATH):
        self.schemes = schemes
        self.json_path = Path(json_path)

    @property
    def serialized_attributes(self) -> list[str]:
        return ["schemes"]

    def __iter__(self):
        yield from self.schemes.values()

    def __getitem__(self, scheme: str):
        return self.schemes.__getitem__(scheme.upper())

    def __setitem__(self, key: str, value):
        self.schemes.__setitem__(key.upper(), value)

    def __len__(self) -> int:
        return len(self.schemes)

    def to_dict(self):
        return {"schemes": self.schemes}

    @classmethod
    def from_dict(cls, dct: Mapping) -> CCSchemeDataset:
        return cls(dct["schemes"])

    @classmethod
    def from_web(cls, only_schemes: set[str] | None = None) -> CCSchemeDataset:
        schemes = {}
        for scheme, sources in CCScheme.methods.items():
            if only_schemes is not None and scheme not in only_schemes:
                continue
            try:
                schemes[scheme] = CCScheme.from_web(scheme, sources.keys())
            except Exception as e:
                logger.warning(f"Could not download CC scheme: {scheme} due to error {e}.")
        return cls(schemes)
