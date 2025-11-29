from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar


class PDFConverter(ABC):
    HAS_JSON_OUTPUT: ClassVar[bool]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "HAS_JSON_OUTPUT" not in cls.__dict__:
            raise TypeError(f"{cls.__name__} must define HAS_JSON_OUTPUT")

    @abstractmethod
    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path | None = None) -> bool:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @classmethod
    def get_name(cls) -> str:
        return cls.__name__.lower().replace("converter", "")
