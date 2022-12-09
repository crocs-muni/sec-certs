from __future__ import annotations

import logging
from datetime import date
from typing import ClassVar

import sec_certs.utils.helpers as helpers
from sec_certs.sample.cc import CommonCriteriaCert
from sec_certs.serialization.json import ComplexSerializableType

logger = logging.getLogger(__name__)


class CommonCriteriaMaintenanceUpdate(CommonCriteriaCert, ComplexSerializableType):
    pandas_columns: ClassVar[list[str]] = [
        "dgst",
        "name",
        "report_link",
        "st_link",
        "related_cert_digest",
        "maintenance_date",
    ]

    def __init__(
        self,
        name: str,
        report_link: str,
        st_link: str,
        state: CommonCriteriaCert.InternalState | None,
        pdf_data: CommonCriteriaCert.PdfData | None,
        heuristics: CommonCriteriaCert.Heuristics | None,
        related_cert_digest: str,
        maintenance_date: date,
    ):
        super().__init__(
            "",
            "",
            name,
            "",
            "",
            "",
            None,
            None,
            report_link,
            st_link,
            "",
            "",
            set(),
            set(),
            state,
            pdf_data,
            heuristics,
        )
        self.related_cert_digest = related_cert_digest
        self.maintenance_date = maintenance_date

    @property
    def serialized_attributes(self) -> list[str]:
        return ["dgst"] + list(self.__class__.__init__.__code__.co_varnames)[1:]

    @property
    def dgst(self) -> str:
        if not self.name:
            raise RuntimeError("MaintenanceUpdate digest can't be computed, because name of update is missing.")
        return "cert_" + self.related_cert_digest + "_update_" + helpers.get_first_16_bytes_sha256(self.name)

    @property
    def pandas_tuple(self) -> tuple:
        return tuple([getattr(self, x) for x in CommonCriteriaMaintenanceUpdate.pandas_columns])

    @classmethod
    def from_dict(cls, dct: dict) -> CommonCriteriaMaintenanceUpdate:
        dct.pop("dgst")
        return cls(*(tuple(dct.values())))

    @classmethod
    def get_updates_from_cc_cert(cls, cert: CommonCriteriaCert) -> list[CommonCriteriaMaintenanceUpdate]:
        if cert.maintenance_updates is None:
            raise RuntimeError("Dataset was probably not built correctly - this should not be happening.")

        return [
            cls(
                x.maintenance_title,
                x.maintenance_report_link,
                x.maintenance_st_link,
                None,
                None,
                None,
                cert.dgst,
                x.maintenance_date,
            )
            for x in cert.maintenance_updates
            if (
                x.maintenance_title is not None
                and x.maintenance_report_link is not None
                and x.maintenance_st_link is not None
                and x.maintenance_date is not None
            )
        ]
