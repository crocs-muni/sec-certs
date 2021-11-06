from typing import List, Set, Dict


class DependencyFinder:

    dependencies = {}

    @staticmethod
    def _update_direct_references(referenced_by: Dict, cert_id: str, this_cert_id: str) -> None:
        if cert_id not in referenced_by:
            referenced_by[cert_id] = []
        if this_cert_id not in referenced_by[cert_id]:
            referenced_by[cert_id].append(this_cert_id)

    @staticmethod
    def _build_cert_references(certificates: Dict):
        referenced_by = {}

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

        referenced_by_indirect = {}

        for cert_id in referenced_by.keys():
            referenced_by_indirect[cert_id] = set()
            for item in referenced_by[cert_id]:
                referenced_by_indirect[cert_id].add(item)

        new_change_detected = True
        while new_change_detected:
            new_change_detected = False
            certs_id_list = referenced_by.keys()

            for cert_id in certs_id_list:
                tmp_referenced_by_indirect_nums = referenced_by_indirect[cert_id].copy()
                for referencing in tmp_referenced_by_indirect_nums:
                    if referencing in referenced_by.keys():
                        tmp_referencing = referenced_by_indirect[referencing].copy()
                        newly_discovered_references = [x for x in tmp_referencing if
                                                       x not in referenced_by_indirect[cert_id]]
                        referenced_by_indirect[cert_id].update(newly_discovered_references)
                        new_change_detected = True if newly_discovered_references else False

        return referenced_by, referenced_by_indirect

    @staticmethod
    def _get_affecting_directly(cert: str, referenced_by_direct: Dict) -> Set:
        filter_direct = set()

        for cert_id in referenced_by_direct:
            if cert in referenced_by_direct[cert_id]:
                filter_direct.add(cert_id)

        return filter_direct

    @staticmethod
    def _get_affecting_indirectly(cert: str, referenced_by_indirect: Dict) -> Set:
        filter_indirect = set()

        for cert_id in referenced_by_indirect:
            if cert in referenced_by_indirect[cert_id]:
                filter_indirect.add(cert_id)

        return filter_indirect

    @staticmethod
    def _get_affected_directly(cert: str, referenced_by_direct: Dict):
        return referenced_by_direct.get(cert, None)

    @staticmethod
    def _get_affected_indirectly(cert: str, referenced_by_indirect: Dict):
        return referenced_by_indirect.get(cert, None)

    @staticmethod
    def fit(certificates: Dict) -> None:
        referenced_by_direct, referenced_by_indirect = DependencyFinder._build_cert_references(certificates)

        for dgst in certificates:
            cert_id = certificates[dgst].pdf_data.cert_id

            if not cert_id:
                continue

            # init
            DependencyFinder.dependencies[dgst] = {}

            DependencyFinder.dependencies[dgst]["directly_affected_by"] = \
                DependencyFinder._get_affected_directly(cert_id, referenced_by_direct)

            DependencyFinder.dependencies[dgst]["indirectly_affected_by"] = \
                DependencyFinder._get_affected_indirectly(cert_id, referenced_by_indirect)

            DependencyFinder.dependencies[dgst]["directly_affecting"] = \
                DependencyFinder._get_affecting_directly(cert_id, referenced_by_direct)

            DependencyFinder.dependencies[dgst]["indirectly_affecting"] = \
                DependencyFinder._get_affecting_indirectly(cert_id, referenced_by_indirect)

        print()
    

    @staticmethod
    def predict(cert) -> Set:
        pass
