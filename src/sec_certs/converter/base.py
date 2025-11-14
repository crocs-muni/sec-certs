from abc import ABC, abstractmethod
from pathlib import Path


class PDFConverter(ABC):
    @abstractmethod
    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path | None = None) -> bool:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @classmethod
    def get_name(cls) -> str:
        return cls.__name__.lower().replace("converter", "")

    @classmethod
    def has_json_output(cls) -> bool:
        return False
