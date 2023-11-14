from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(eq=True, frozen=True)
class CertificateId:
    """
    A Common Criteria certificate id.
    """

    scheme: str
    raw: str

    def _canonical_fr(self) -> str:
        def pad_last_segment_with_zero(id_str: str) -> str:
            splitted = id_str.split("/")
            if len(splitted) > 1:
                num = splitted[-1].zfill(2)
                return f"{''.join(splitted[:-1])}/{num}"
            return id_str

        new_cert_id = self.clean
        rules = [
            "(?:Rapport de certification|Certification Report) ([0-9]+[/-_][0-9]+(?:[vV][1-9])?(?:[_/-][MSR][0-9]+)?)",
            "(?:ANSS[Ii]|DCSSI)(?:-CC)?[- ]([0-9]+[/-_][0-9]+(?:[vV][1-9])?(?:[_/-][MSR][0-9]+)?)",
            "([0-9]+[/-_][0-9]+(?:[vV][1-9])?(?:[_/-][MSR][0-9]+)?)",
        ]
        for rule in rules:
            if match := re.match(rule, new_cert_id):
                return pad_last_segment_with_zero("ANSSI-CC-" + match.group(1).replace("_", "/").replace("V", "v"))

        return new_cert_id

    def _canonical_de(self) -> str:
        def extract_parts(bsi_parts: list[str]) -> tuple:
            cert_num = None
            cert_version = None
            cert_year = None

            if len(bsi_parts) > 3:
                cert_num = bsi_parts[3]
            if len(bsi_parts) > 4:
                if bsi_parts[4].startswith("V") or bsi_parts[4].startswith("v"):
                    cert_version = bsi_parts[4].upper()  # get version in uppercase
                else:
                    cert_year = bsi_parts[4]
            if len(bsi_parts) > 5:
                cert_year = bsi_parts[5]

            return cert_num, cert_version, cert_year

        bsi_parts = self.clean.split("-")

        cert_num, cert_version, cert_year = extract_parts(bsi_parts)

        # reconstruct BSI number again
        new_cert_id = "BSI-DSZ-CC"
        if cert_num is not None:
            new_cert_id += "-" + cert_num
        if cert_version is not None:
            new_cert_id += "-" + cert_version
        if cert_year is not None:
            new_cert_id += "-" + cert_year

        return new_cert_id

    def _canonical_es(self) -> str:
        cert_id = self.clean
        spain_parts = cert_id.split("-")
        cert_year = spain_parts[0]
        cert_batch = spain_parts[1].lstrip("0")
        cert_num = spain_parts[3].lstrip("0")

        if "v" in cert_num:
            cert_num = cert_num[: cert_num.find("v")]
        if "V" in cert_num:
            cert_num = cert_num[: cert_num.find("V")]

        new_cert_id = f"{cert_year}-{cert_batch}-INF-{cert_num.strip()}"  # drop version # TODO: Maybe do not drop?

        return new_cert_id

    def _canonical_it(self):
        new_cert_id = self.clean
        if not new_cert_id.endswith("/RC"):
            new_cert_id = new_cert_id + "/RC"

        return new_cert_id

    def _canonical_in(self):
        return self.clean.replace(" ", "")

    def _canonical_se(self):
        return self.clean.replace(" ", "")

    def _canonical_uk(self):
        new_cert_id = self.clean
        if match := re.match("CERTIFICATION REPORT No. P([0-9]+[A-Z]?)", new_cert_id):
            new_cert_id = "CRP" + match.group(1)
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
        if match := re.match("Certification No. (C[0-9]+)", new_cert_id):
            return match.group(1)
        if match := re.search("CRP-(C[0-9]+)-", new_cert_id):
            return match.group(1)
        return new_cert_id

    def _canonical_no(self):
        new_cert_id = self.clean
        cert_num = int(new_cert_id.split("-")[1])
        return f"SERTIT-{cert_num:03}"

    def _canonical_nl(self):
        new_cert_id = self.clean
        if new_cert_id.startswith("CC-"):
            new_cert_id = f"NSCIB-{new_cert_id}"
        if not new_cert_id.endswith("-CR"):
            new_cert_id = f"{new_cert_id}-CR"
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
            "ES": self._canonical_es,
            "IT": self._canonical_it,
            "IN": self._canonical_in,
            "SE": self._canonical_se,
            "UK": self._canonical_uk,
            "CA": self._canonical_ca,
            "JP": self._canonical_jp,
            "NO": self._canonical_no,
            "NL": self._canonical_nl,
        }

        if self.scheme in schemes:
            return schemes[self.scheme]()
        else:
            return self.clean


def canonicalize(cert_id_str: str, scheme: str) -> str:
    return CertificateId(scheme, cert_id_str).canonical
