from typing import Dict, List, Optional, Set, Tuple, Union

from sec_certs.sample.common_criteria import CommonCriteriaCert

Certificates = Dict[str, CommonCriteriaCert]
ReferencedByDirect = Dict[str, List[str]]
ReferencedByIndirect = Dict[str, Set[str]]
Dependencies = Dict[str, Dict[str, Union[Optional[List[str]], Optional[Set[str]]]]]


class DependencyFinder:
    def __init__(self):
        self.dependencies: Dependencies = {}

    @staticmethod
    def _update_direct_references(referenced_by: ReferencedByDirect, cert_id: str, this_cert_id: str) -> None:
        if cert_id not in referenced_by:
            referenced_by[cert_id] = []
        if this_cert_id not in referenced_by[cert_id]:
            referenced_by[cert_id].append(this_cert_id)

    @staticmethod
    def _process_references(referenced_by: ReferencedByDirect, referenced_by_indirect: ReferencedByIndirect):
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
    def _build_cert_references(certificates: Certificates) -> Tuple[ReferencedByDirect, ReferencedByIndirect]:
        referenced_by: ReferencedByDirect = {}

        for cert_obj in certificates.values():
            if cert_obj.pdf_data.report_keywords is None:
                continue

            this_cert_id = None
            if cert_obj.pdf_data.processed_cert_id is not None:
                this_cert_id = cert_obj.pdf_data.processed_cert_id

            # Direct reference
            for cert_id in cert_obj.pdf_data.report_keywords["rules_cert_id"]:
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
    def _get_affecting_directly(cert: str, referenced_by_direct: ReferencedByDirect) -> Optional[Set[str]]:
        filter_direct = set()

        for cert_id in referenced_by_direct:
            if cert in referenced_by_direct[cert_id]:
                filter_direct.add(cert_id)

        return filter_direct if filter_direct else None

    @staticmethod
    def _get_affecting_indirectly(cert: str, referenced_by_indirect: ReferencedByIndirect) -> Optional[Set[str]]:
        filter_indirect = set()

        for cert_id in referenced_by_indirect:
            if cert in referenced_by_indirect[cert_id]:
                filter_indirect.add(cert_id)

        return filter_indirect if filter_indirect else None

    @staticmethod
    def _get_affected_directly(cert: str, referenced_by_direct: ReferencedByDirect) -> Optional[List[str]]:
        return referenced_by_direct.get(cert, None)

    @staticmethod
    def _get_affected_indirectly(cert: str, referenced_by_indirect: ReferencedByIndirect) -> Optional[Set[str]]:
        return referenced_by_indirect.get(cert, None)

    def fit(self, certificates: Certificates) -> None:
        referenced_by_direct, referenced_by_indirect = DependencyFinder._build_cert_references(certificates)

        for dgst in certificates:
            cert_id = certificates[dgst].pdf_data.cert_id
            self.dependencies[dgst] = {}

            if not cert_id:
                continue

            self.dependencies[dgst]["directly_affected_by"] = DependencyFinder._get_affected_directly(
                cert_id, referenced_by_direct
            )

            self.dependencies[dgst]["indirectly_affected_by"] = DependencyFinder._get_affected_indirectly(
                cert_id, referenced_by_indirect
            )

            self.dependencies[dgst]["directly_affecting"] = DependencyFinder._get_affecting_directly(
                cert_id, referenced_by_direct
            )

            self.dependencies[dgst]["indirectly_affecting"] = DependencyFinder._get_affecting_indirectly(
                cert_id, referenced_by_indirect
            )

    def get_directly_affected_by(self, dgst: str) -> Optional[List[str]]:
        res = self.dependencies[dgst].get("directly_affected_by", None)
        return list(res) if res else None

    def get_indirectly_affected_by(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("indirectly_affected_by", None)
        return set(res) if res else None

    def get_directly_affecting(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("directly_affecting", None)
        return set(res) if res else None

    def get_indirectly_affecting(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("indirectly_affecting", None)
        return set(res) if res else None
