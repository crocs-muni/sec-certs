from typing import Callable, Dict, List, Optional, Set, Tuple

from sec_certs.sample.certificate import Certificate, References

Certificates = Dict[str, Certificate]
ReferencedByDirect = Dict[str, Set[str]]
ReferencedByIndirect = Dict[str, Set[str]]
Dependencies = Dict[str, Dict[str, Optional[Set[str]]]]
IDLookupFunc = Callable[[Certificate], str]
ReferenceLookupFunc = Callable[[Certificate], Set[str]]


class DependencyFinder:
    """
    The class assigns references of other certificate instances for each instance.
    Adheres to sklearn BaseEstimator interface.
    The fit is called on a dictionary of certificates, builds a hashmap of references, and assigns references for each certificate in the dictionary.
    """

    def __init__(self):
        self.dependencies: Dependencies = {}

    @staticmethod
    def _update_direct_references(referenced_by: ReferencedByDirect, cert_id: str, this_cert_id: str) -> None:
        if cert_id not in referenced_by:
            referenced_by[cert_id] = set()
        if this_cert_id not in referenced_by[cert_id]:
            referenced_by[cert_id].add(this_cert_id)

    @staticmethod
    def _process_references(referenced_by: ReferencedByDirect, referenced_by_indirect: ReferencedByIndirect) -> None:
        new_change_detected = True
        while new_change_detected:
            new_change_detected = False
            certs_id_list = referenced_by.keys()

            for cert_id in certs_id_list:
                tmp_referenced_by_indirect_nums = referenced_by_indirect[cert_id].copy()
                for referencing in tmp_referenced_by_indirect_nums:
                    if referencing in referenced_by.keys():
                        tmp_referencing = referenced_by_indirect[referencing].copy()
                        newly_discovered_references = [
                            x for x in tmp_referencing if x not in referenced_by_indirect[cert_id]
                        ]
                        referenced_by_indirect[cert_id].update(newly_discovered_references)
                        new_change_detected = True if newly_discovered_references else False

    @staticmethod
    def _build_cert_references(
        certificates: Certificates, id_func: IDLookupFunc, ref_lookup_func: ReferenceLookupFunc
    ) -> Tuple[ReferencedByDirect, ReferencedByIndirect]:
        referenced_by: ReferencedByDirect = {}

        for cert_obj in certificates.values():
            refs = ref_lookup_func(cert_obj)
            if refs is None:
                continue

            this_cert_id = id_func(cert_obj)

            # Direct reference
            for cert_id in refs:
                if cert_id != this_cert_id and this_cert_id is not None:
                    DependencyFinder._update_direct_references(referenced_by, cert_id, this_cert_id)

        referenced_by_indirect: ReferencedByIndirect = {}

        for cert_id in referenced_by.keys():
            referenced_by_indirect[cert_id] = set()
            for item in referenced_by[cert_id]:
                referenced_by_indirect[cert_id].add(item)

        DependencyFinder._process_references(referenced_by, referenced_by_indirect)
        return referenced_by, referenced_by_indirect

    @staticmethod
    def _get_referencing_directly(cert: str, referenced_by_direct: ReferencedByDirect) -> Optional[Set[str]]:
        filter_direct = set()

        for cert_id in referenced_by_direct:
            if cert in referenced_by_direct[cert_id]:
                filter_direct.add(cert_id)

        return filter_direct if filter_direct else None

    @staticmethod
    def _get_referencing_indirectly(cert: str, referenced_by_indirect: ReferencedByIndirect) -> Optional[Set[str]]:
        filter_indirect = set()

        for cert_id in referenced_by_indirect:
            if cert in referenced_by_indirect[cert_id]:
                filter_indirect.add(cert_id)

        return filter_indirect if filter_indirect else None

    @staticmethod
    def _get_referenced_directly(cert: str, referenced_by_direct: ReferencedByDirect) -> Optional[Set[str]]:
        return referenced_by_direct.get(cert, None)

    @staticmethod
    def _get_referenced_indirectly(cert: str, referenced_by_indirect: ReferencedByIndirect) -> Optional[Set[str]]:
        return referenced_by_indirect.get(cert, None)

    def fit(self, certificates: Certificates, id_func: IDLookupFunc, ref_lookup_func: ReferenceLookupFunc) -> None:
        """
        Builds a list of references and assigns references for each certificate instance.

        :param Certificates certificates: dictionary of certificates with hashes as key
        :param IDLookupFunc id_func: lookup function for cert id
        :param ReferenceLookupFunc ref_lookup_func: lookup for references
        :return None: None
        """
        referenced_by_direct, referenced_by_indirect = DependencyFinder._build_cert_references(
            certificates, id_func, ref_lookup_func
        )

        for dgst in certificates:
            cert_id = id_func(certificates[dgst])
            self.dependencies[dgst] = {}

            if not cert_id:
                continue

            self.dependencies[dgst]["directly_referenced_by"] = DependencyFinder._get_referenced_directly(
                cert_id, referenced_by_direct
            )

            self.dependencies[dgst]["indirectly_referenced_by"] = DependencyFinder._get_referenced_indirectly(
                cert_id, referenced_by_indirect
            )

            self.dependencies[dgst]["directly_referencing"] = DependencyFinder._get_referencing_directly(
                cert_id, referenced_by_direct
            )

            self.dependencies[dgst]["indirectly_referencing"] = DependencyFinder._get_referencing_indirectly(
                cert_id, referenced_by_indirect
            )

    def _get_directly_referenced_by(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("directly_referenced_by", None)
        return set(res) if res else None

    def _get_indirectly_referenced_by(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("indirectly_referenced_by", None)
        return set(res) if res else None

    def _get_directly_referencing(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("directly_referencing", None)
        return set(res) if res else None

    def _get_indirectly_referencing(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("indirectly_referencing", None)
        return set(res) if res else None

    def predict_single_cert(self, dgst: str) -> References:
        """
        Method returns references object for specified certificate digest

        :param str dgst: certificate digest
        :return References: References object
        """
        return References(
            self._get_directly_referenced_by(dgst),
            self._get_indirectly_referenced_by(dgst),
            self._get_directly_referencing(dgst),
            self._get_indirectly_referencing(dgst),
        )

    def predict(self, dgst_list: List[str]) -> Dict[str, References]:
        """
        Method returns references for a list of certificate digests

        :param List[str] dgst_list: List of certificate hashes
        :return Dict[str, References]: Dict with certificate hash and References object.
        """
        cert_references = {}

        for dgst in dgst_list:
            cert_references[dgst] = self.predict_single_cert(dgst)

        return cert_references
