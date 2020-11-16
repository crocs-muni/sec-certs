from unittest import TestCase
from pathlib import Path
from tempfile import TemporaryDirectory, mkstemp
from datetime import date, datetime
import json
import filecmp
import shutil
import os

from sec_certs.dataset import CCDataset, DatasetJSONDecoder, DatasetJSONEncoder
from sec_certs.certificate import CommonCriteriaCert


class TestCommonCriteriaOOP(TestCase):
    def setUp(self):
        self.test_data_dir = Path(__file__).parent / 'data' / 'test_cc_oop'
        self.crt_one = CommonCriteriaCert('Access Control Devices and Systems',
                                      'NetIQ Identity Manager 4.7',
                                      'NetIQ Corporation',
                                      'SE',
                                      {'ALC_FLR.2',
                                       'EAL3+'},
                                      date(2020, 6, 15),
                                      date(2025, 6, 15),
                                      'http://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ\u00ae%20Identity%20Manager%204.7.pdf',
                                      'http://www.commoncriteriaportal.org/files/epfiles/ST%20-%20NetIQ%20Identity%20Manager%204.7.pdf',
                                      'csv + html',
                                      'http://www.commoncriteriaportal.org/files/epfiles/Certifikat%20CCRA%20-%20NetIQ%20Identity%20Manager%204.7_signed.pdf',
                                      'https://www.netiq.com/',
                                      set(),
                                      set())

        self.crt_two = CommonCriteriaCert('Access Control Devices and Systems',
                                          'Magic SSO V4.0',
                                          'Dreamsecurity Co., Ltd.',
                                          'KR',
                                          set(),
                                          date(2019, 11, 15),
                                          date(2024, 11, 15),
                                          'http://www.commoncriteriaportal.org/files/epfiles/KECS-CR-19-70%20Magic%20SSO%20V4.0(eng)%20V1.0.pdf',
                                          'http://www.commoncriteriaportal.org/files/epfiles/Magic_SSO_V4.0-ST-v1.4_EN.pdf',
                                          'csv + html',
                                          None,
                                          'https://www.dreamsecurity.com/',
                                          {CommonCriteriaCert.ProtectionProfile('Korean National Protection Profile for Single Sign On V1.0',
                                                                                'http://www.commoncriteriaportal.org/files/ppfiles/KECS-PP-0822-2017%20Korean%20National%20PP%20for%20Single%20Sign%20On%20V1.0(eng).pdf')},
                                          set())

        pp = CommonCriteriaCert.ProtectionProfile('sample_pp', 'http://sample.pp')
        update = CommonCriteriaCert.MaintainanceReport(date(1900, 1, 1), 'Sample maintainance', 'https://maintainance.up', 'https://maintainance.up')
        self.fictional_cert = CommonCriteriaCert('Sample category',
                                                 'Sample certificate name',
                                                 'Sample manufacturer',
                                                 'Sample scheme',
                                                 {'Sample security level'},
                                                 date(1900, 1, 2),
                                                 date(1900, 1, 3),
                                                 'http://path.to/report/link',
                                                 'http://path.to/st/link',
                                                 'custom',
                                                 'http://path.to/cert/link',
                                                 'http://path.to/manufacturer/web',
                                                 {pp},
                                                 {update})
        self.template_dataset = CCDataset({self.crt_one.dgst: self.crt_one, self.crt_two.dgst: self.crt_two}, Path('/fictional/path/to/dataset'), 'toy dataset', 'toy dataset description')
        self.template_dataset.timestamp = datetime(2020, 11, 16, hour=17, minute=4, second=14, microsecond=770153)

    def test_certificate_input_sanity(self):
        self.assertEqual(self.crt_one.report_link,
                         'http://www.commoncriteriaportal.org/files/epfiles/Certification%20Report%20-%20NetIQ®%20Identity%20Manager%204.7.pdf',
                         'Report link contains some improperly escaped characters.')

    @staticmethod
    def equal_to_json(referential_path, obj):
        fd, path = mkstemp()
        try:
            with os.fdopen(fd, 'w') as handle:
                json.dump(obj, handle, cls=DatasetJSONEncoder, indent=4)

            return filecmp.cmp(referential_path, path)
        finally:
            os.remove(path)

    @staticmethod
    def equal_from_json(referential_path, obj):
        with open(referential_path, 'r') as handle:
            new_obj = json.load(handle, cls=DatasetJSONDecoder)
        return obj == new_obj

    def test_cert_to_json(self):
        self.assertTrue(self.equal_to_json(self.test_data_dir / 'fictional_cert.json', self.fictional_cert),
                        'The certificate serialized to json differs from a template.')

    def test_dataset_to_json(self):
        self.assertTrue(self.equal_to_json(self.test_data_dir / 'toy_dataset.json', self.template_dataset),
                        'The dataset serialized to json differs from a template.')

    def test_cert_from_json(self):
        self.assertTrue(self.equal_from_json(self.test_data_dir / 'fictional_cert.json',  self.fictional_cert),
                        'The certificate serialized from json differs from a template.')

    def test_dataset_from_json(self):
        self.assertTrue(self.equal_from_json(self.test_data_dir / 'toy_dataset.json', self.template_dataset),
                        'The dataset serialized from json differs from a template.')

    def test_build_empty_dataset(self):
        with TemporaryDirectory() as tmp_dir:
            dset = CCDataset({}, Path(tmp_dir), 'sample_dataset', 'sample dataset description')
            dset.get_certs_from_web(to_download=False, get_archived=False, get_active=False)
        self.assertEqual(len(dset), 0, 'The dataset should contain 0 files.')

    def test_build_dataset(self):
        with TemporaryDirectory() as tmp_dir:
            dataset_path = Path(tmp_dir)
            os.mkdir(dataset_path / 'web')
            shutil.copyfile(self.test_data_dir / 'cc_products_active.csv', dataset_path / 'web' / 'cc_products_active.csv')
            shutil.copyfile(self.test_data_dir / 'cc_products_active.html', dataset_path / 'web' / 'cc_products_active.html')

            dset = CCDataset({}, dataset_path, 'sample_dataset', 'sample dataset description')
            dset.get_certs_from_web(keep_metadata=False, to_download=False, get_archived=False, get_active=True)

            self.assertEqual(len(os.listdir(dataset_path)), 0,
                             'Meta files (csv, html) were not deleted properly albeit this was explicitly required.')

        self.assertEqual(len(dset), 2, 'The dataset should contain 2 files.')
        self.assertTrue(self.crt_one in dset, 'The dataset does not contain the template certificate.')
        self.assertEqual(dset, self.template_dataset, 'The loaded dataset does not match the template dataset.')
