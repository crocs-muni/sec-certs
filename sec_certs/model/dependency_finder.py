from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Set, Tuple

from sec_certs.sample.certificate import Certificate
from sec_certs.serialization.json import ComplexSerializableType

Certificates = Dict[str, Certificate]
ReferencedByDirect = Dict[str, Set[str]]
ReferencedByIndirect = Dict[str, Set[str]]
Dependencies = Dict[str, Dict[str, Optional[Set[str]]]]
IDLookupFunc = Callable[[Certificate], str]
ReferenceLookupFunc = Callable[[Certificate], Set[str]]


@dataclass
class References(ComplexSerializableType):
    directly_referenced_by: Optional[Set[str]] = field(default=None)
    indirectly_referenced_by: Optional[Set[str]] = field(default=None)
    directly_referencing: Optional[Set[str]] = field(default=None)
    indirectly_referencing: Optional[Set[str]] = field(default=None)


class DependencyFinder:
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

    def get_directly_referenced_by(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("directly_referenced_by", None)
        return set(res) if res else None

    def get_indirectly_referenced_by(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("indirectly_referenced_by", None)
        return set(res) if res else None

    def get_directly_referencing(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("directly_referencing", None)
        return set(res) if res else None

    def get_indirectly_referencing(self, dgst: str) -> Optional[Set[str]]:
        res = self.dependencies[dgst].get("indirectly_referencing", None)
        return set(res) if res else None

    def get_references(self, dgst: str) -> References:
        return References(
            self.get_directly_referenced_by(dgst),
            self.get_indirectly_referenced_by(dgst),
            self.get_directly_referencing(dgst),
            self.get_indirectly_referencing(dgst),
        )
