from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from sec_certs.sample.certificate import Certificate, References

CertSubType = TypeVar("CertSubType", bound=Certificate)
Certificates = dict[str, CertSubType]
ReferencedByDirect = dict[str, set[str]]
ReferencedByIndirect = dict[str, set[str]]
ReferencesType = dict[str, dict[str, set[str] | None]]
IDMapping = dict[str, list[str]]
UnknownReferences = dict[str, set[str]]
IDLookupFunc = Callable[[CertSubType], str]
ReferenceLookupFunc = Callable[[CertSubType], set[str]]


# TODO: All of this can and should be rewritten on top of networkx or some other graph library.
class ReferenceFinder:
    """
    The class assigns references of other certificate instances for each instance.
    Adheres to sklearn BaseEstimator interface.
    The fit is called on a dictionary of certificates, builds a hashmap of references, and assigns references for each certificate in the dictionary.
    """

    def __init__(self: ReferenceFinder) -> None:
        self.references: ReferencesType = {}
        self.id_mapping: IDMapping = {}
        self._fitted: bool = False

    def _create_id_mapping(self, certificates: Certificates, id_func: IDLookupFunc) -> None:
        """
        Create the ID mapping of certificate IDs to certificate digests.

        Necessary for handling duplicates.
        """
        # Create a mapping of certificate ID to certificate digests with that ID.
        for dgst in certificates:
            cert_id = id_func(certificates[dgst])
            c_list = self.id_mapping.setdefault(cert_id, [])
            c_list.append(dgst)

        # Sort digests in ID mapping to have deterministic behavior.
        # The certificate with the first digest will be used with that ID, others will be discarded.
        for digests in self.id_mapping.values():
            digests.sort()

    def _compute_indirect_references(self, referenced_by: ReferencedByDirect) -> ReferencedByIndirect:
        """
        Compute indirect references via a BFS algorithm.
        """
        referenced_by_indirect: ReferencedByIndirect = {}

        # Populate with direct references.
        certs_id_list = referenced_by.keys()
        for cert_id in certs_id_list:
            referenced_by_indirect[cert_id] = set()
            for item in referenced_by[cert_id]:
                referenced_by_indirect[cert_id].add(item)

        # Flood in the indirect ones.
        new_change_detected = True
        while new_change_detected:
            new_change_detected = False

            for cert_id in certs_id_list:
                tmp_referenced_by_indirect_nums = referenced_by_indirect[cert_id].copy()
                for referencing in tmp_referenced_by_indirect_nums:
                    if referencing in certs_id_list:
                        tmp_referencing = referenced_by_indirect[referencing].copy()
                        newly_discovered_references = [
                            x for x in tmp_referencing if x not in referenced_by_indirect[cert_id]
                        ]
                        referenced_by_indirect[cert_id].update(newly_discovered_references)
                        if newly_discovered_references:
                            new_change_detected = True
        return referenced_by_indirect

    def _build_referenced_by(
        self, certificates: Certificates, ref_lookup_func: ReferenceLookupFunc
    ) -> tuple[ReferencedByDirect, ReferencedByIndirect]:
        referenced_by: ReferencedByDirect = {}

        for this_cert_id, cert_digests in self.id_mapping.items():
            # Take the first certificate digest from the ID mapping (to ensure deterministic behavior and resolve duplicates).
            # TODO: A better approach for handling duplicates in the future would be nice.
            cert_dgst = cert_digests[0]
            cert_obj = certificates[cert_dgst]

            refs = ref_lookup_func(cert_obj)
            if refs is None:
                continue

            # Process direct reference
            # All are added here, the unknown ones are filtered later on.
            for cert_id in refs:
                if cert_id == this_cert_id:
                    continue
                referenced_by.setdefault(cert_id, set())
                referenced_by[cert_id].add(this_cert_id)

        # Now do the indirect ones
        referenced_by_indirect = self._compute_indirect_references(referenced_by)
        return referenced_by, referenced_by_indirect

    def _get_reverse_references(
        self, cert_id: str, references: ReferencedByDirect | ReferencedByIndirect
    ) -> set[str] | None:
        result = set()

        for other_id in references:
            if cert_id in references[other_id]:
                result.add(other_id)

        return result if result else None

    def _build_referencing(
        self, referenced_by_direct: ReferencedByDirect, referenced_by_indirect: ReferencedByIndirect
    ) -> None:
        for cert_id, cert_digests in self.id_mapping.items():
            cert_dgst = cert_digests[0]
            self.references[cert_dgst] = {
                "directly_referenced_by": referenced_by_direct.get(cert_id, None),
                "indirectly_referenced_by": referenced_by_indirect.get(cert_id, None),
                "directly_referencing": self._get_reverse_references(cert_id, referenced_by_direct),
                "indirectly_referencing": self._get_reverse_references(cert_id, referenced_by_indirect),
            }

    def fit(self, certificates: Certificates, id_func: IDLookupFunc, ref_lookup_func: ReferenceLookupFunc) -> None:
        """
        Builds a list of references and assigns references for each certificate instance.

        :param Certificates certificates: dictionary of certificates with hashes as key
        :param IDLookupFunc id_func: lookup function for cert id
        :param ReferenceLookupFunc ref_lookup_func: lookup for references
        """
        if self._fitted:
            raise ValueError("Finder already fitted")
        # Create the ID mapping first so that we can resolve duplicates.
        self._create_id_mapping(certificates, id_func)

        # Build the referenced_by first
        referenced_by_direct, referenced_by_indirect = self._build_referenced_by(certificates, ref_lookup_func)

        # Build the referencing second (this actually writes into self.references).
        self._build_referencing(referenced_by_direct, referenced_by_indirect)
        self._fitted = True

    @property
    def unknown_references(self) -> UnknownReferences:
        """
        Get the unknown references in the fitted dataset (to unknown certificate IDs, not in the dataset during fit).
        """
        if not self._fitted:
            return {}
        result = {}
        for cert_id, digests in self.id_mapping.items():
            cert_digest = digests[0]
            cert_references = self.references[cert_digest]
            direct_refs = cert_references["directly_referencing"]
            if not direct_refs:
                continue
            unknowns = set(filter(lambda refd_cert_id: refd_cert_id not in self.id_mapping, direct_refs))
            if unknowns:
                result[cert_id] = unknowns
        return result

    @property
    def duplicates(self) -> IDMapping:
        """
        Get the duplicates in the fitted dataset.

        :return IDMapping: Mapping of certificate ID to digests that share it.
        """
        if not self._fitted:
            return {}
        return {cert_id: digests for cert_id, digests in self.id_mapping.items() if len(digests) > 1}

    def predict_single_cert(self, dgst: str, keep_unknowns: bool = True) -> References:
        """
        Get the references object for specified certificate digest.

        :param dgst: certificate digest
        :param keep_unknowns: Whether to keep references to unknown certificate IDs
        :return References: References object
        """
        if not self._fitted:
            raise ValueError("Finder not yet fitted")

        def wrap(res):
            if not res:
                return None
            # If we do not want the unknown references, filter them here.
            if not keep_unknowns:
                res = set(filter(lambda cert_id: cert_id in self.id_mapping, res))
            return set(res) if res else None

        if dgst not in self.references:
            return References()

        return References(
            wrap(self.references[dgst].get("directly_referenced_by", None)),
            wrap(self.references[dgst].get("indirectly_referenced_by", None)),
            wrap(self.references[dgst].get("directly_referencing", None)),
            wrap(self.references[dgst].get("indirectly_referencing", None)),
        )

    def predict(self, dgst_list: list[str], keep_unknowns: bool = True) -> dict[str, References]:
        """
        Get the references for a list of certificate digests.

        :param dgst_list: List of certificate digests.
        :param keep_unknowns: Whether to keep references to and from unknown certificate IDs
        :return Dict[str, References]: Dict with certificate hash and References object.
        """
        if not self._fitted:
            raise ValueError("Finder not yet fitted")
        cert_references = {}

        for dgst in dgst_list:
            cert_references[dgst] = self.predict_single_cert(dgst, keep_unknowns=keep_unknowns)

        return cert_references
