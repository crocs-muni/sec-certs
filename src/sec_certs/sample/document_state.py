from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sec_certs.serialization.json import ComplexSerializableType


@dataclass
class DocumentState(ComplexSerializableType):
    download_ok: bool = False  # Whether download went OK
    convert_ok: bool = False  # Whether conversion went OK
    extract_ok: bool = False  # Whether extraction went OK
    convert_garbage: bool = False  # deprecated

    pdf_hash: str | None = None
    txt_hash: str | None = None
    json_hash: str | None = None

    _pdf_path: Path | None = None
    _txt_path: Path | None = None
    _json_path: Path | None = None

    def is_ok_to_download(self, fresh: bool = True) -> bool:
        return True if fresh else not self.download_ok

    def is_ok_to_convert(self, fresh: bool = True) -> bool:
        return self.download_ok if fresh else self.download_ok and not self.convert_ok

    def is_ok_to_analyze(self, fresh: bool = True) -> bool:
        if fresh:
            return self.download_ok and self.convert_ok
        else:
            return self.download_ok and self.convert_ok and not self.extract_ok

    @property
    def pdf_path(self) -> Path:
        if not self._pdf_path:
            raise ValueError(f"pdf_path not set on {type(self)}")
        return self._pdf_path

    @pdf_path.setter
    def pdf_path(self, pth: str | Path | None) -> None:
        self._pdf_path = Path(pth) if pth else None

    @property
    def txt_path(self) -> Path:
        if not self._txt_path:
            raise ValueError(f"txt_path not set on {type(self)}")
        return self._txt_path

    @txt_path.setter
    def txt_path(self, pth: str | Path | None) -> None:
        self._txt_path = Path(pth) if pth else None

    @property
    def json_path(self) -> Path:
        if not self._json_path:
            raise ValueError(f"json_path not set on {type(self)}")
        return self._json_path

    @json_path.setter
    def json_path(self, pth: str | Path | None) -> None:
        self._json_path = Path(pth) if pth else None

    @property
    def serialized_attributes(self) -> list[str]:
        return ["download_ok", "convert_ok", "extract_ok", "pdf_hash", "txt_hash", "json_hash"]
