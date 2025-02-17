from __future__ import annotations

import logging
import shutil
from abc import ABC
from pathlib import Path

from sec_certs.serialization.json import ComplexSerializableType, get_class_fullname, only_backed

logger = logging.getLogger(__name__)


class JSONPathDataset(ComplexSerializableType, ABC):
    _json_path: Path | None

    def __init__(self, json_path: str | Path | None = None):
        super().__init__()
        self.json_path = Path(json_path) if json_path is not None else None

    @property
    def is_backed(self) -> bool:
        """
        Returns whether the dataset is backed by a JSON file.
        """
        return self.json_path is not None

    @property
    def json_path(self) -> Path | None:
        return self._json_path

    @json_path.setter
    def json_path(self, new_path: str | Path | None) -> None:
        if new_path is None:
            self._json_path = None
            return

        new_path = Path(new_path)
        if new_path.is_dir():
            raise ValueError(f"Json path of {get_class_fullname(self)} cannot be a directory.")

        self._json_path = new_path

    @only_backed()
    def move_dataset(self, new_json_path: str | Path) -> None:
        logger.info(f"Moving {get_class_fullname(self)} dataset to {new_json_path}.")
        new_json_path = Path(new_json_path)
        new_json_path.parent.mkdir(parents=True, exist_ok=True)

        if self.json_path and self.json_path.exists():
            shutil.move(self.json_path, new_json_path)
            self.json_path = new_json_path
        else:
            self.json_path = new_json_path
            self.to_json()

    @classmethod
    def from_json(cls, input_path: str | Path, is_compressed: bool = False):
        dset = super().from_json(input_path, is_compressed)
        dset.json_path = Path(input_path)
        return dset
