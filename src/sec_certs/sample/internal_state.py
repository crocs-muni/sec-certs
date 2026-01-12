from __future__ import annotations

from dataclasses import dataclass, field

from sec_certs.sample.document_state import DocumentState
from sec_certs.serialization.json import ComplexSerializableType


@dataclass
class InternalState(ComplexSerializableType):
    """
    Holds internal state of the certificate, whether downloads and converts of individual components succeeded. Also
    holds information about errors and paths to the files.
    """

    report: DocumentState = field(default_factory=DocumentState)
    st: DocumentState = field(default_factory=DocumentState)
    cert: DocumentState = field(default_factory=DocumentState)
