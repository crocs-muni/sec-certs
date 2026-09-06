"""Data model for SESIP certificates"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import date
from typing import Any


class SESIPCertificate:
    # single sesip CERT

    @dataclass
    class IndexData:
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
            values: dict[str, Any] = {k: (v.strip() or None) for k, v in row.items() if k in known}
            if raw_date := values.get("issue_date"):
                values["issue_date"] = date.fromisoformat(raw_date)
            return cls(**values)

    def __init__(self, cert_id: str, index_data: SESIPCertificate.IndexData | None = None):
        self.cert_id = cert_id
        self.index_data = index_data if index_data else SESIPCertificate.IndexData()

    @classmethod
    def from_index_row(cls, row: dict[str, str]) -> SESIPCertificate:
        if not row.get("cert_id"):
            raise ValueError("row has no cert_id, which is the primary key")
        return cls(cert_id=row["cert_id"], index_data=cls.IndexData.from_row(row))

    def __repr__(self) -> str:
        return f"SESIPCertificate({self.cert_id})"

    def __str__(self) -> str:
        return f"{self.cert_id}: {self.index_data.product or '<unknown product>'}"
