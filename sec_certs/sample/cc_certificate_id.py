from dataclasses import dataclass
from typing import List, Tuple


@dataclass(eq=True, frozen=True)
class CertificateId:
    """
    A Common Criteria certificate id.
    """

    scheme: str
    raw: str

    def _canonical_fr(self) -> str:
        # TODO: Unify ANSSI vs DCSSI vs Certification Report vs Rapport de certification
        new_cert_id = self.clean

        # This currently only handles the ANSSI-CC-0000... ids.
        if not new_cert_id.startswith("ANSS"):
            return new_cert_id

        if new_cert_id.startswith("ANSSi"):  # mistyped ANSSi
            new_cert_id = "ANSSI" + new_cert_id[4:]

        # Bug - getting out of index - ANSSI-2009/30
        # TMP solution
        # TODO: Fix me, @georgefi
        if len(new_cert_id) >= len("ANSSI-CC-0000") + 1:
            if (
                new_cert_id[len("ANSSI-CC-0000")] == "_"
            ):  # _ instead of / after year (ANSSI-CC-2010_40 -> ANSSI-CC-2010/40)
                new_cert_id = new_cert_id[: len("ANSSI-CC-0000")] + "/" + new_cert_id[len("ANSSI-CC-0000") + 1 :]

        if "_" in new_cert_id:  # _ instead of -
            new_cert_id = new_cert_id.replace("_", "-")

        return new_cert_id

    def _canonical_de(self) -> str:
        def extract_parts(bsi_parts: List[str]) -> Tuple:
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

        # start_year = 1996
        # limit_year = datetime.now().year + 1
        bsi_parts = self.clean.split("-")

        cert_num, cert_version, cert_year = extract_parts(bsi_parts)
        # if cert_year is None:
        #     for year in range(start_year, limit_year):
        #         cert_id_possible = cert_id + "-" + str(year)
        #
        #         if cert_id_possible in all_cert_ids:
        #             # we found version with year
        #             cert_year = str(year)
        #             break

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
        cert_batch = spain_parts[1]
        cert_num = spain_parts[3]

        if "v" in cert_num:
            cert_num = cert_num[: cert_num.find("v")]
        if "V" in cert_num:
            cert_num = cert_num[: cert_num.find("V")]

        new_cert_id = f"{cert_year}-{cert_batch}-INF-{cert_num.strip()}"  # drop version

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
            # TODO: Unify UK CRP... vs Certification REPORT No.
            # TODO: Unify JP C0000 vs JISEC-...
            # TODO: Unify US (-CR and no -CR)
        }

        if self.scheme in schemes:
            return schemes[self.scheme]()
        else:
            return self.clean
