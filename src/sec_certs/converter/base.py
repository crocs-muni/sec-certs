from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar


class PDFConverter(ABC):
    HAS_JSON_OUTPUT: ClassVar[bool]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "HAS_JSON_OUTPUT" not in cls.__dict__:
            raise TypeError(f"{cls.__name__} must define HAS_JSON_OUTPUT")

    def convert(self, pdf_path: Path, txt_path: Path, json_path: Path | None = None) -> bool:
        """
        Convert a PDF file, writing the text to `txt_path` and, for converters that produce one, the
        serialized document to `json_path`.

        :param pdf_path: Path to the to-be-converted PDF file.
        :param txt_path: Path to the resulting text file.
        :param json_path: Path to the resulting JSON file.
        :return: A boolean if the conversion was successful.
        """
        tmp_txt = txt_path.with_name(f"{txt_path.name}.tmp")
        tmp_json = json_path.with_name(f"{json_path.name}.tmp") if json_path and self.HAS_JSON_OUTPUT else None

        if not self._convert(pdf_path, tmp_txt, tmp_json):
            return False

        tmp_txt.replace(txt_path)
        if json_path is not None and tmp_json is not None:
            tmp_json.replace(json_path)
        return True

    @abstractmethod
    def _convert(self, pdf_path: Path, txt_path: Path, json_path: Path | None = None) -> bool:
        raise NotImplementedError("Not meant to be implemented by the base class.")

    @classmethod
    def get_name(cls) -> str:
        return cls.__name__.lower().replace("converter", "")
