from __future__ import annotations

import re
from dataclasses import dataclass

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


@dataclass(eq=True, frozen=True)
class CertificateId:
    """
    A Common Criteria certificate id.
    """

    scheme: str
    raw: str

    def _canonical_fr(self) -> str:
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["FR"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                year = _parse_year(groups["year"])
                counter = groups["counter"]
                doc = groups.get("doc")
                version = groups.get("version")
                new_cert_id = f"ANSSI-CC-{year}/{counter}"
                if doc:
                    new_cert_id += f"-{doc}"
                if version:
                    new_cert_id += f"v{version}"
                break

        return new_cert_id

    def _canonical_de(self) -> str:
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["DE"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                s = groups.get("s")
                counter = groups["counter"]
                version = groups.get("version")
                year = _parse_year(groups.get("year"))
                doc = groups.get("doc")
                new_cert_id = "BSI-DSZ-CC"
                if s:
                    new_cert_id += f"-{s}"
                new_cert_id += f"-{counter}"
                if version:
                    new_cert_id += f"-{version.upper()}"
                if year:
                    new_cert_id += f"-{year}"
                if doc:
                    new_cert_id += f"-{doc}"
                break

        return new_cert_id

    def _canonical_us(self) -> str:
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["US"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                year = _parse_year(groups["year"])
                counter = groups["counter"]
                cc = groups.get("cc")
                vid = groups.get("VID")
                new_cert_id = "CCEVS-VR"
                if cc:
                    new_cert_id += f"-{cc}"
                if vid:
                    new_cert_id += f"-{vid}"
                new_cert_id += f"-{counter}"
                new_cert_id += f"-{year}"
                break

        return new_cert_id

    def _canonical_my(self) -> str:
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["MY"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                digit = groups["digit"]
                counter = groups["counter"]
                version = groups["version"]
                new_cert_id = f"ISCB-{digit}-RPT-C{counter}-CR-{version.lower()}"
                break

        return new_cert_id

    def _canonical_es(self) -> str:
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["ES"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                year = _parse_year(groups["year"])
                project = groups["project"]
                counter = groups["counter"]
                # Version is intentionally cut here, as it seems to refer to an internal version of the report.
                # version = groups["version"]
                new_cert_id = f"{year}-{project}-INF-{counter}"
                break
        return new_cert_id

    def _canonical_in(self):
        return self.clean.replace(" ", "")

    def _canonical_se(self):
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["SE"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                year = _parse_year(groups["year"])
                counter = int(groups["counter"])
                new_cert_id = f"CSEC{year}{counter:03}"
        return new_cert_id

    def _canonical_uk(self):
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["UK"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                counter = groups["counter"]
                new_cert_id = f"CRP{counter}"
                break
        return new_cert_id

    def _canonical_ca(self):
        new_cert_id = self.clean
        if new_cert_id.endswith("-CR"):
            new_cert_id = new_cert_id[:-3]
        if new_cert_id.endswith("P"):
            new_cert_id = new_cert_id[:-1]
        return new_cert_id.replace(" ", "-")

    def _canonical_jp(self):
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["JP"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                counter = groups["counter"]
                digit = groups.get("digit")
                year = _parse_year(groups.get("year"))
                new_cert_id = f"JISEC-CC-CRP-C{counter}"
                if digit:
                    new_cert_id += f"-{digit}"
                if year:
                    new_cert_id += f"-{year}"
                break
        return new_cert_id

    def _canonical_kr(self):
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["KR"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                word = groups["word"]
                counter = int(groups["counter"])
                year = _parse_year(groups["year"])
                new_cert_id = f"KECS-{word}-{counter:04}-{year}"
                break
        return new_cert_id

    def _canonical_no(self):
        new_cert_id = self.clean
        cert_num = int(new_cert_id.split("-")[1])
        return f"SERTIT-{cert_num:03}"

    def _canonical_nl(self):
        new_cert_id = self.clean
        if new_cert_id.startswith("CC-"):
            new_cert_id = f"NSCIB-{new_cert_id}"
        if not re.match(".*-(CR|MA|MR)[0-9]*$", new_cert_id):
            new_cert_id = f"{new_cert_id}-CR"
        return new_cert_id

    def _canonical_au(self):
        new_cert_id = self.clean
        for rule in rules["cc_cert_id"]["AU"]:
            if match := re.match(rule, new_cert_id):
                groups = match.groupdict()
                counter = groups["counter"]
                year_s = groups["year"]
                if len(year_s) < len(counter):
                    # Hack for some mistakes in their ordering
                    year_s, counter = counter, year_s
                year = _parse_year(year_s)
                new_cert_id = f"Certificate Number: {year}/{counter}"
                break
        return new_cert_id

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
        # We have rules for some schemes to make canonical cert_ids.
        schemes = {
            "FR": self._canonical_fr,
            "DE": self._canonical_de,
            "US": self._canonical_us,
            "MY": self._canonical_my,
            "ES": self._canonical_es,
            "IN": self._canonical_in,
            "SE": self._canonical_se,
            "UK": self._canonical_uk,
            "CA": self._canonical_ca,
            "JP": self._canonical_jp,
            "NO": self._canonical_no,
            "NL": self._canonical_nl,
            "AU": self._canonical_au,
            "KR": self._canonical_kr,
            # SG is canonical by default
            # IT is canonucal by default
        }

        if self.scheme in schemes:
            return schemes[self.scheme]()
        else:
            return self.clean


def canonicalize(cert_id_str: str, scheme: str) -> str:
    return CertificateId(scheme, cert_id_str).canonical
