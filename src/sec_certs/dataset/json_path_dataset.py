from __future__ import annotations

import logging
import shutil
from abc import ABC
from pathlib import Path

from sec_certs.serialization.json import ComplexSerializableType, get_class_fullname

logger = logging.getLogger(__name__)


class JSONPathDataset(ComplexSerializableType, ABC):
    _json_path: Path

    @property
    def json_path(self) -> Path:
        return self._json_path

    @json_path.setter
    def json_path(self, new_path: str | Path) -> None:
        new_path = Path(new_path)
        if new_path.is_dir():
            raise ValueError(f"Json path of {get_class_fullname(self)} cannot be a directory.")

        self._json_path = new_path

    def move_dataset(self, new_json_path: str | Path) -> None:
        logger.info(f"Moving {get_class_fullname(self)} dataset to {new_json_path}")
        new_json_path = Path(new_json_path)
        new_json_path.parent.mkdir(parents=True, exist_ok=True)

        if self.json_path.exists():
            shutil.move(str(self.json_path), str(new_json_path))
            self.json_path = new_json_path
        else:
            self.json_path = new_json_path
            self.to_json()

    @classmethod
    def from_json(cls, input_path: str | Path, is_compressed: bool = False):
        dset = super().from_json(input_path, is_compressed)
        dset.json_path = Path(input_path)
        return dset
