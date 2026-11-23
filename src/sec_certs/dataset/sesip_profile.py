from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, ClassVar

from sec_certs.dataset.json_path_dataset import JSONPathDataset
from sec_certs.serialization.json import ComplexSerializableType


class SESIPProfileDataset(JSONPathDataset, ComplexSerializableType):
    """SESIP profile families - name pattern, issuer, documents and PSA level"""

    BUNDLED_PATH: ClassVar[Path] = Path(__file__).parent.parent / "sesip_profiles.json"

    def __init__(self, profiles: dict[str, dict[str, Any]], json_path: str | Path | None = None):
        super().__init__(json_path)
        self.profiles = profiles

    def __iter__(self) -> Iterator[dict[str, Any]]:
        yield from self.profiles.values()

    def __getitem__(self, family: str) -> dict[str, Any]:
        return self.profiles[family]

    def __contains__(self, family: object) -> bool:
        return family in self.profiles

    def __len__(self) -> int:
        return len(self.profiles)

    def to_dict(self) -> dict[str, Any]:
        return {"profiles": self.profiles}

    @classmethod
    def from_dict(cls, dct: Mapping) -> SESIPProfileDataset:
        return cls(dct["profiles"])

    @classmethod
    def from_bundled(cls, json_path: str | Path | None = None) -> SESIPProfileDataset:
        """The catalog in sec-certs package"""
        profiles = json.loads(cls.BUNDLED_PATH.read_text(encoding="utf-8"))
        return cls({profile["family"]: profile for profile in profiles}, json_path)
