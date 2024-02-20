from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property

from sec_certs.cert_rules import rules


def _parse_year(year: str | None) -> int | None:
    if year is None:
        return None
    y = int(year)
    if y < 50:
        return y + 2000
    elif y < 100:
        return y + 1900
    else:
        return y


def FR(meta) -> str:
    year = _parse_year(meta["year"])
    counter = meta["counter"]
    doc = meta.get("doc")
    version = meta.get("version")
    cert_id = f"ANSSI-CC-{year}/{counter}"
    if doc:
        cert_id += f"-{doc}"
    if version:
        cert_id += f"v{version}"
    return cert_id


def DE(meta) -> str:
    s = meta.get("s")
    counter = meta["counter"]
    version = meta.get("version")
    year = _parse_year(meta.get("year"))
    doc = meta.get("doc")
    cert_id = "BSI-DSZ-CC"
    if s:
        cert_id += f"-{s}"
    cert_id += f"-{counter}"
    if version:
        cert_id += f"-{version.upper()}"
    if year:
        cert_id += f"-{year}"
    if doc:
        cert_id += f"-{doc}"
    return cert_id


def US(meta) -> str:
    counter = meta["counter"]
    cc = meta.get("cc")
    vid = meta.get("VID")
    year = _parse_year(meta.get("year"))
    cert_id = "CCEVS-VR"
    if cc:
        cert_id += f"-{cc}"
    if vid:
        cert_id += f"-{vid}"
    cert_id += f"-{counter}"
    if year:
        cert_id += f"-{year}"
    return cert_id


def MY(meta) -> str:
    digit = meta["digit"]
    counter = meta["counter"]
    version = meta["version"]
    return f"ISCB-{digit}-RPT-C{counter}-CR-{version.lower()}"


def ES(meta) -> str:
    year = _parse_year(meta["year"])
    project = meta["project"]
    counter = meta["counter"]
    # Version is intentionally cut here, as it seems to refer to an internal version of the report.
    # version = groups["version"]
    return f"{year}-{project}-INF-{counter}"


def IN(meta) -> str:
    lab = meta["lab"]
    vendor = meta["vendor"]
    level = meta["level"]
    number1, number2 = meta["number1"], meta["number2"]
    return f"IC3S/{lab}/{vendor}/{level}/{number1}/{number2}"


def SE(meta) -> str:
    year = _parse_year(meta["year"])
    counter = int(meta["counter"])
    return f"CSEC{year}{counter:03}"


def UK(meta) -> str:
    counter = meta["counter"]
    return f"CRP{counter}"


def CA(meta) -> str:
    if "lab" in meta:
        year = _parse_year(meta.get("year"))
        number = meta["number"]
        lab = meta["lab"]
        cert_id = f"{number}-{lab}"
        if year:
            cert_id += f"-{year}"
        return cert_id
    else:
        number1 = meta["number1"]
        digit = meta["digit"]
        number2 = meta["number2"]
        return f"{number1}-{digit}-{number2}"


def JP(meta) -> str:
    counter = meta["counter"]
    digit = meta.get("digit")
    year = _parse_year(meta.get("year"))
    cert_id = f"JISEC-CC-CRP-C{counter}"
    if digit:
        cert_id += f"-{digit}"
    if year:
        cert_id += f"-{year}"
    return cert_id


def KR(meta) -> str:
    word = meta["word"]
    counter = int(meta["counter"])
    year = _parse_year(meta["year"])
    return f"KECS-{word}-{counter:04}-{year}"


def TR(meta) -> str:
    prefix = meta["prefix"]
    number = meta["number"]
    return f"{prefix}/TSE-CCCS-{number}"


def NO(meta) -> str:
    counter = int(meta["counter"])
    return f"SERTIT-{counter:03}"


def NL(meta) -> str:
    core = meta["core"]
    doc = meta.get("doc")
    if doc is None:
        doc = "CR"
    return f"NSCIB-CC-{core}-{doc}"


def AU(meta) -> str:
    counter = meta["counter"]
    year_s = meta["year"]
    if len(year_s) < len(counter):
        # Hack for some mistakes in their ordering
        year_s, counter = counter, year_s
    year = _parse_year(year_s)
    return f"Certificate Number: {year}/{counter}"


def SG(meta) -> str:
    year = meta["year"]
    counter = meta["counter"]
    return f"CSA_CC_{year}{counter}"


def IT(meta) -> str:
    lab = meta.get("lab")
    counter = meta["counter"]
    year = _parse_year(meta["year"])
    cert_id = "OCSI/CERT/"
    if lab:
        cert_id += f"{lab}/"
    cert_id += f"{counter}/{year}/RC"
    return cert_id


# We have rules for some schemes to make canonical cert_ids.
schemes = {
    "FR": FR,
    "DE": DE,
    "US": US,
    "MY": MY,
    "ES": ES,
    "IN": IN,
    "SE": SE,
    "UK": UK,
    "CA": CA,
    "JP": JP,
    "NO": NO,
    "NL": NL,
    "AU": AU,
    "KR": KR,
    "TR": TR,
    "SG": SG,
    "IT": IT,
}


@dataclass(frozen=True)
class CertificateId:
    """
    A Common Criteria certificate id.
    """

    scheme: str
    raw: str

    @cached_property
    def meta(self):
        for rule in rules["cc_cert_id"][self.scheme]:
            if match := re.match(rule, self.clean):
                return match.groupdict()
        return {}

    @property
    def clean(self) -> str:
        """
        The clean version of this certificate id.
        """
        return self.raw.replace("\N{HYPHEN}", "-").strip()

    @property
    def canonical(self) -> str:
        """
        The canonical version of this certificate id.
        """
        clean = self.clean

        if self.scheme in schemes:
            return schemes[self.scheme](self.meta)
        else:
            return clean

    def __str__(self):
        return self.canonical

    def __hash__(self):
        return hash((self.scheme, self.raw))

    def __eq__(self, other):
        if isinstance(other, str):
            return self.canonical == other
        if not isinstance(other, CertificateId):
            return False
        return self.canonical == other.canonical and self.scheme == other.scheme


def canonicalize(cert_id_str: str, scheme: str) -> str:
    return CertificateId(scheme, cert_id_str).canonical
