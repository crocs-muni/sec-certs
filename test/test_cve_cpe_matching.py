from unittest import TestCase
from sec_certs.dataset import CCDataset
from sec_certs.certificate import CommonCriteriaCert
from sec_certs.cpe import CPEDataset, CPE
from sec_certs.cve import CVEDataset, CVE
from pathlib import Path


class TestCPEandCVEMatching(TestCase):
    def setUp(self) -> None:
        self.test_data_dir = Path(__file__).parent / 'data' / 'test_cpe_cve'
        self.cc_dset = CCDataset.from_json(self.test_data_dir / 'vulnerable_dataset.json')
        self.cc_dset.compute_heuristics(update_json=False)

        self.cpes = [CPE("cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*", "IBM Security Access Manager For Enterprise Single Sign-On 8.2.2"),
                CPE("cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*", "IBM Security Key Lifecycle Manager 2.6.0.1"),
                CPE("cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*", "Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress"),
                CPE("cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*", "Tracker Software PDF-XChange Lite Printer 6.0.320.0")]
        self.cpe_dset = CPEDataset({x.uri: x for x in self.cpes})

        self.cves = [CVE('CVE-2017-1732', ['cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*'], CVE.Impact(5.3, 'MEDIUM', 3.9, 1.4)),
                     CVE('CVE-2019-4513', ['cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*'], CVE.Impact(8.2, 'HIGH', 3.9, 4.2))]
        self.cve_dset = CVEDataset({x.cve_id: x for x in self.cves})

    def test_load_cpe_dataset(self):
        json_cpe_dset = CPEDataset.from_json(self.test_data_dir / 'auxillary_datasets' / 'cpe_dataset.json')
        self.assertEqual(self.cpe_dset, json_cpe_dset, 'CPE template dataset does not match CPE dataset loaded from json.')

    def test_cpe_lookup_dicts(self):
        self.assertEqual(self.cpe_dset.vendors, {'ibm', 'tracker-software', 'semperplugins'},
                         'The set of versions in CPE dataset does not match template')
        alt_lookup = {x: set(y) for x, y in self.cpe_dset.vendor_to_versions.items()}
        self.assertEqual(alt_lookup, {'ibm': {'8.2.2', '2.6.0.1'}, 'semperplugins': {'1.3.6.4'}, 'tracker-software': {'6.0.320.0'}},
                         'The CPE lookup dictionary vendor->version of CPE dataset does not match template.')
        self.assertEqual(self.cpe_dset.vendor_version_to_cpe, {('ibm', '8.2.2'): [CPE('cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*', 'IBM Security Access Manager For Enterprise Single Sign-On 8.2.2')], ('ibm', '2.6.0.1'): [CPE('cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*', 'IBM Security Key Lifecycle Manager 2.6.0.1')], ('semperplugins', '1.3.6.4'): [CPE('cpe:2.3:a:semperplugins:all_in_one_seo_pack:1.3.6.4:*:*:*:*:wordpress:*:*', 'Semper Plugins All in One SEO Pack 1.3.6.4 for WordPress')], ('tracker-software', '6.0.320.0'): [CPE('cpe:2.3:a:tracker-software:pdf-xchange_lite_printer:6.0.320.0:*:*:*:*:*:*:*', 'Tracker Software PDF-XChange Lite Printer 6.0.320.0')]},
                         'The CPE lookup dictionary (vendor,version)->cpe does not match the template.')

    def test_cve_lookup_dicts(self):
        alt_lookup = {x: set(y) for x,y in self.cve_dset.cpes_to_cve_lookup.items()}
        self.assertEqual(alt_lookup, {'cpe:2.3:a:ibm:security_access_manager_for_enterprise_single_sign-on:8.2.2:*:*:*:*:*:*:*': set(['CVE-2017-1732', 'CVE-2019-4513'])},
                         'The CVE lookup dicionary cve-> affected cpes does not match the template')

    def test_load_cve_dataset(self):
        json_cve_dset = CVEDataset.from_json(self.test_data_dir / 'auxillary_datasets' / 'cve_dataset.json')
        self.assertEqual(self.cve_dset, json_cve_dset, 'CVE template dataset does not match CVE dataset loaded from json.')

    def test_match_cpe(self):
        self.assertTrue(self.cpes[0] in [x[1] for x in self.cc_dset['c01e5375331b25dc'].heuristics.cpe_matches], 'The CPE matching algorithm did not find the right CPE.')
        self.assertTrue(len(self.cc_dset['c01e5375331b25dc'].heuristics.cpe_matches) == 1, 'Exactly one CPE match should be found.')

    def test_find_related_cves(self):
        self.cc_dset['c01e5375331b25dc'].heuristics.verified_cpe_matches = [self.cpes[0]]
        self.cc_dset.compute_related_cves()
        self.assertCountEqual([x.cve_id for x in self.cves], self.cc_dset['c01e5375331b25dc'].heuristics.related_cves, 'The computed CVEs do not match the excpected CVEs')

    def test_version_extraction(self):
        self.assertEqual(self.cc_dset['c01e5375331b25dc'].heuristics.extracted_versions, ['8.2'], 'The version extracted from the certificate does not match the template')
        new_cert = CommonCriteriaCert('', '', 'IDOneClassIC Card : ID-One Cosmo 64 RSA v5.4 and applet IDOneClassIC v1.0 embedded on P5CT072VOP', '', '',
                                      '', None, None, '', '', '', '', '', set(), set(), None, None, None)
        new_cert.compute_heuristics_version()
        self.assertEqual(set(new_cert.heuristics.extracted_versions), {'5.4', '1.0'}, 'The extracted versions do not match the template.')


