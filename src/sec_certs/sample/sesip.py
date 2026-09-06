"""Data model for SESIP certificates"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import date
from typing import Any

from sec_certs.serialization.json import ComplexSerializableType
from sec_certs.utils.helpers import get_first_16_bytes_sha256


class SESIPCertificate(ComplexSerializableType):
    # single sesip CERT

    @dataclass
    class IndexData(ComplexSerializableType):
        """row of the TrustCB index table"""

        product: str | None = None
        developer: str | None = None
        evaluator: str | None = None
        compliance: str | None = None  # not augmented
        standard: str | None = None
        status: str | None = None
        issue_date: date | None = None
        cert_link: str | None = None
        st_link: str | None = None

        @classmethod
        def from_row(cls, row: dict[str, str]) -> SESIPCertificate.IndexData:
            known = {f.name for f in fields(cls)}
            # empty cell -> key missing -> field defaults to None
            return cls.from_dict({k: v.strip() for k, v in row.items() if k in known and v.strip()})

        @classmethod
        def from_dict(cls, dct: dict) -> SESIPCertificate.IndexData:
            values = dict(dct)
            if isinstance(values.get("issue_date"), str):
                values["issue_date"] = date.fromisoformat(values["issue_date"])
            return cls(**values)

    def __init__(self, cert_id: str, index_data: SESIPCertificate.IndexData | None = None):
        self.cert_id = cert_id
        self.index_data = index_data if index_data else SESIPCertificate.IndexData()

    @classmethod
    def from_index_row(cls, row: dict[str, str]) -> SESIPCertificate:
        if not row.get("cert_id"):
            raise ValueError("row has no cert_id, which is the primary key")
        return cls(cert_id=row["cert_id"], index_data=cls.IndexData.from_row(row))

    @property
    def dgst(self) -> str:
        return get_first_16_bytes_sha256(self.cert_id)

    @property
    def name(self) -> str | None:
        return self.index_data.product

    @property
    def manufacturer(self) -> str | None:
        return self.index_data.developer

    def to_dict(self) -> dict[str, Any]:
        return {"dgst": self.dgst, **super().to_dict()}

    @classmethod
    def from_dict(cls, dct: dict) -> SESIPCertificate:
        values = dict(dct)
        values.pop("dgst", None)
        return cls(**values)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SESIPCertificate) and self.dgst == other.dgst

    def __hash__(self) -> int:
        return hash(self.dgst)

    def __repr__(self) -> str:
        return f"SESIPCertificate({self.cert_id})"

    def __str__(self) -> str:
        return f"{self.cert_id}: {self.index_data.product or '<unknown product>'}"
