from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class DocumentLayer(str, Enum):
    BODY = "body"
    FURNITURE = "furniture"


class DocumentView(ABC):
    @property
    @abstractmethod
    def artifact_path(self) -> Path:
        """
        Path to the file this view reads.
        """
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @abstractmethod
    def get_full_text(self, layers: set[DocumentLayer] | None = None) -> str:
        """
        Get the whole unformatted text of the document

        :param layers: content layers to include, all of them when None.
        """
        raise NotImplementedError("Not meant to be implemented by the base class.")

    def __str__(self) -> str:
        return "/".join(self.artifact_path.parts[-4:])
