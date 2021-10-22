import copy
import datetime
import tempfile
from unittest import TestCase
from sec_certs.dataset.common_criteria import CCDataset
from sec_certs.sample.common_criteria import CommonCriteriaCert
from sec_certs.sample.protection_profile import ProtectionProfile
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.sample.cpe import CPE
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.cve import CVE
from pathlib import Path
from typing import ClassVar, Dict
import shutil

import tests.data.test_cpe_cve


class TestCommonCriteriaHeuristics(TestCase):
    dataset_json_path: ClassVar[Path] = Path(tests.data.test_cpe_cve.__path__[0]) / 'vulnerable_dataset.json'
    data_dir_path: ClassVar[Path] = dataset_json_path.parent

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir: ClassVar[tempfile.TemporaryDirectory] = tempfile.TemporaryDirectory()
        shutil.copytree(cls.data_dir_path, cls.tmp_dir.name, dirs_exist_ok=True)

        cls.cc_dset: CCDataset = CCDataset.from_json(Path(cls.tmp_dir.name) / 'vulnerable_dataset.json')
        cls.cc_dset.process_protection_profiles()
        cls.cc_dset.download_all_pdfs()
        cls.cc_dset.convert_all_pdfs()
        cls.cc_dset._extract_data()
        cls.cc_dset._compute_heuristics()

        cls.cpes = [
            CPE("cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*",
                "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2"),
            CPE("cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*",
                "IBM Security Key Lifecycle Manager 2.6.0.1"),
            CPE("cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*",
                "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress"),
            CPE("cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*",
                "Tracker Software PDF-XChange Lite Printer 6.0.320.0")
        ]
        cls.cpe_dset = CPEDataset({x.uri: x for x in cls.cpes})

        cls.cves = [
            CVE('CVE-2017-1732',
                ['cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*'],
                None,
                CVE.Impact(5.3, 'MEDIUM', 3.9, 1.4),
                '2021-05-26T04:15Z',
                'IBM Security Access Manager for Enterprise Single Sign-On 8.2.2 does not set the secure attribute on authorization tokens or session cookies. Attackers may be able to get the cookie values by sending a http:// link to a user or by planting this link in a site the user goes to. The cookie will be sent to the insecure link and the attacker can then obtain the cookie value by snooping the traffic. IBM X-Force ID: 134913.'),
            CVE('CVE-2019-4513',
                ['cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*'],
                None,
                CVE.Impact(8.2, 'HIGH', 3.9, 4.2),
                '2000-05-26T04:15Z',
                'IBM Security Access Manager for Enterprise Single Sign-On 8.2.2 is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose sensitive information or consume memory resources. IBM X-Force ID: 164555.')
        ]
        cls.cve_dset = CVEDataset({x.cve_id: x for x in cls.cves})

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp_dir.cleanup()

    def test_load_cpe_dataset(self):
        json_cpe_dset = CPEDataset.from_json(self.data_dir_path / 'auxillary_datasets' / 'cpe_dataset.json')
        self.assertEqual(self.cpe_dset, json_cpe_dset, 'CPE template dataset does not match CPE dataset loaded from json.')

    def test_cpe_lookup_dicts(self):
        self.assertEqual(self.cpe_dset.vendors, {'ibm', 'tracker-software', 'semperplugins'},
                         'The set of versions in CPE dataset does not match template')
        self.assertEqual(self.cpe_dset.vendor_to_versions, {'ibm': {'8.2.2', '2.6.0.1'}, 'semperplugins': {'1.3.6.4'}, 'tracker-software': {'6.0.320.0'}},
                         'The CPE lookup dictionary vendor->version of CPE dataset does not match template.')
        self.assertEqual(self.cpe_dset.vendor_version_to_cpe, {('ibm', '8.2.2'): {CPE('cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*', 'IBM Security Access Manager For Enterprise Single Sign-On 8.2.2')}, ('ibm', '2.6.0.1'): {CPE('cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*', 'IBM Security Key Lifecycle Manager 2.6.0.1')}, ('semperplugins', '1.3.6.4'): {CPE('cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*', 'Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress')}, ('tracker-software', '6.0.320.0'): {CPE('cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*', 'Tracker Software PDF-XChange Lite Printer 6.0.320.0')}},
                         'The CPE lookup dictionary (vendor,version)->cpe does not match the template.')

    def test_cve_lookup_dicts(self):
        alt_lookup = {x: set(y) for x, y in self.cve_dset.cpe_to_cve_ids_lookup.items()}
        self.assertEqual(alt_lookup, {'cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*': set(self.cves)},
                         'The CVE lookup dicionary cve-> affected cpes does not match the template')

    def test_load_cve_dataset(self):
        json_cve_dset = CVEDataset.from_json(self.data_dir_path / 'auxillary_datasets' / 'cve_dataset.json')
        self.assertEqual(self.cve_dset, json_cve_dset, 'CVE template dataset does not match CVE dataset loaded from json.')

    def test_match_cpe(self):
        self.assertTrue(self.cpes[0] in [x[1] for x in self.cc_dset['ebd276cca70fd723'].heuristics.cpe_matches], 'The CPE matching algorithm did not find the right CPE.')
        self.assertTrue(len(self.cc_dset['ebd276cca70fd723'].heuristics.cpe_matches) == 1, 'Exactly one CPE match should be found.')

    def test_find_related_cves(self):
        self.cc_dset['ebd276cca70fd723'].heuristics.verified_cpe_matches = [self.cpes[0]]
        self.cc_dset.compute_related_cves()

        evaluated_cves = copy.deepcopy(self.cves)
        for cve in evaluated_cves:
            cve.vulnerable_certs = ['ebd276cca70fd723']

        self.assertCountEqual(evaluated_cves, self.cc_dset['ebd276cca70fd723'].heuristics.related_cves, 'The computed CVEs do not match the excpected CVEs')

    def test_version_extraction(self):
        self.assertEqual(self.cc_dset['ebd276cca70fd723'].heuristics.extracted_versions, ['8.2'], 'The version extracted from the sample does not match the template')
        new_cert = CommonCriteriaCert('', '', 'IDOneClassIC Card : ID-One Cosmo 64 RSA v5.4 and applet IDOneClassIC v1.0 embedded on P5CT072VOP', '', '',
                                      '', None, None, '', '', '', '', set(), set(), None, None, None)
        new_cert.compute_heuristics_version()
        self.assertEqual(set(new_cert.heuristics.extracted_versions), {'5.4', '1.0'}, 'The extracted versions do not match the template.')

    def test_cert_lab_heuristics(self):
        self.assertEqual(self.cc_dset['ebd276cca70fd723'].heuristics.cert_lab, ['BSI'])

    def test_cert_id_heuristics(self):
        self.assertEqual(self.cc_dset['ebd276cca70fd723'].heuristics.cert_id, 'BSI-DSZ-CC-0683-2014')

    def test_keywords_heuristics(self):
        extracted_keywords: Dict = self.cc_dset['ebd276cca70fd723'].pdf_data.st_keywords

        self.assertTrue('rules_security_level' in extracted_keywords)
        self.assertEqual(extracted_keywords['rules_security_level']['EAL3'], 1)

        self.assertTrue('rules_security_assurance_components' in extracted_keywords)
        self.assertEqual(extracted_keywords['rules_security_assurance_components']['ADV_ARC.1'], 1)
        self.assertEqual(extracted_keywords['rules_security_assurance_components']['ADV_FSP.3'], 1)
        self.assertEqual(extracted_keywords['rules_security_assurance_components']['ADV_TDS.2'], 1)

        self.assertTrue('rules_crypto_algs' in extracted_keywords)
        self.assertEqual(extracted_keywords['rules_crypto_algs']['AES'], 2)

        self.assertTrue('rules_block_cipher_modes' in extracted_keywords)
        self.assertEqual(extracted_keywords['rules_block_cipher_modes']['CBC'], 2)

    def test_protection_profiles_matching(self):
        artificial_pp: ProtectionProfile = ProtectionProfile('Korean National Protection Profile for Single Sign On V1.0',
                                                             'http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf')
        self.cc_dset['ebd276cca70fd723'].protection_profiles = {artificial_pp}
        expected_pp: ProtectionProfile = ProtectionProfile('Korean National Protection Profile for Single Sign On V1.0',
                                                           'http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf',
                                                           frozenset(['KECS-PP-0822-2017 SSO V1.0']))
        self.cc_dset.process_protection_profiles(to_download=False)
        self.assertSetEqual(self.cc_dset['ebd276cca70fd723'].protection_profiles, {expected_pp})
