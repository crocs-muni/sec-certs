from unittest import TestCase
from pathlib import Path
from tempfile import TemporaryDirectory

from sec_certs.dataset import FIPSDataset, FIPSAlgorithmDataset
from sec_certs.configuration import config
from fips_test_utils import generate_html



def _set_up_dataset(td, certs):
    dataset = FIPSDataset({}, Path(td), 'test_dataset', 'fips_test_dataset')
    generate_html(certs, td + '/test_search.html')
    dataset.get_certs_from_web(test=td + '/test_search.html')
    return dataset


def _set_up_dataset_for_full(td, certs):
    dataset = _set_up_dataset(td, certs)
    dataset.convert_all_pdfs()
    dataset.extract_keywords()
    dataset.extract_certs_from_tables(high_precision=True)
    dataset.algorithms = FIPSAlgorithmDataset.from_json('data/test_fips_oop/algorithms.json')
    dataset.finalize_results()
    return dataset


class TestFipsOOP(TestCase):
    def setUp(self) -> None:
        self.data_dir: Path = Path(__file__).parent / 'data' / 'test_fips_oop'
        self.dataset = FIPSDataset({}, self.data_dir, 'test_dataset', 'fips_test_dataset')
        self.certs_to_parse = [
            ['3099', '2549', '2484', '3038', '2472', '2435', '2471', '1930'],  # openSUSE chunk
            ['23', '24', '25', '26'],
            ['3095', '3651', '3093', '3090', '3197', '3196', '3089', '3195', '3480', '3615', '3194', '3091', '3690',
             '3644', '3527', '3094', '3544', '3096', '3092'],  # microsoft chunk
            ['2630', '2721', '2997', '2441', '2711', '2633', '2798', '3613', '3733', '2908', '2446', '2742', '2447'],
            # redhat chunk
            ['3850', '2779', '2860', '2665', '1883', '3518', '3141', '2590'],  # Document signing chunk
            ['3493', '3495', '3711', '3176', '3488', '3126', '3269', '3524', '3220', '2398', '3543', '2676', '3313',
             '3363', '3608', '3158'],  # Chunk referencing openSSL FIPS Object Module SE
        ]
        config.load(Path('../sec_certs/settings.yaml'))

    def test_size(self):
        for certs in self.certs_to_parse:
            with TemporaryDirectory() as td:
                dataset = _set_up_dataset(td, certs)
                self.assertEqual(len(dataset.certs), len(certs), "Wrong number of parsed certs")

    def test_connections_microsoft(self):
        certs = self.certs_to_parse[2]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)

            self.assertEqual(set(dataset.certs['3095'].processed.connections), {x for x in ['3093', '3096', '3094']})
            self.assertEqual(set(dataset.certs['3651'].processed.connections), {x for x in ['3615']})
            self.assertEqual(set(dataset.certs['3093'].processed.connections), {x for x in ['3090', '3091']})
            self.assertEqual(set(dataset.certs['3090'].processed.connections), {x for x in ['3089']})
            self.assertEqual(set(dataset.certs['3197'].processed.connections),
                             {x for x in ['3195', '3096', '3196', '3644', '3651']})
            self.assertEqual(set(dataset.certs['3196'].processed.connections),
                             {x for x in ['3194', '3091', '3480', '3615']})
            self.assertEqual(set(dataset.certs['3089'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['3195'].processed.connections), {x for x in ['3194', '3091', '3480']})
            self.assertEqual(set(dataset.certs['3480'].processed.connections), {x for x in ['3089']})
            self.assertEqual(set(dataset.certs['3615'].processed.connections), {x for x in ['3089']})
            self.assertEqual(set(dataset.certs['3194'].processed.connections), {x for x in ['3089']})
            self.assertEqual(set(dataset.certs['3091'].processed.connections), {x for x in ['3089']})
            self.assertEqual(set(dataset.certs['3690'].processed.connections), {x for x in ['3644', '3196', '3651']})
            self.assertEqual(set(dataset.certs['3644'].processed.connections), {x for x in ['3615']})
            self.assertEqual(set(dataset.certs['3527'].processed.connections), {x for x in ['3090', '3091']})
            self.assertEqual(set(dataset.certs['3094'].processed.connections), {x for x in ['3090', '3091']})
            self.assertEqual(set(dataset.certs['3544'].processed.connections), {x for x in ['3093', '3096', '3527']})
            self.assertEqual(set(dataset.certs['3096'].processed.connections),
                             {x for x in ['3090', '3194', '3091', '3480']})
            self.assertEqual(set(dataset.certs['3092'].processed.connections),
                             {x for x in ['3093', '3195', '3096', '3644', '3651']})

    def test_connections_redhat(self):
        certs = self.certs_to_parse[3]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)
            self.assertEqual(set(dataset.certs['2630'].processed.connections), {x for x in ['2441']})
            self.assertEqual(set(dataset.certs['2633'].processed.connections), {x for x in ['2441']})
            self.assertEqual(set(dataset.certs['2441'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['2997'].processed.connections), {x for x in ['2711']})
            self.assertEqual(set(dataset.certs['2446'].processed.connections), {x for x in ['2441']})
            self.assertEqual(set(dataset.certs['2447'].processed.connections), {x for x in ['2441']})
            self.assertEqual(set(dataset.certs['3733'].processed.connections), {x for x in ['2441']})
            self.assertEqual(set(dataset.certs['2441'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['2711'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['2908'].processed.connections), {x for x in ['2711']})
            self.assertEqual(set(dataset.certs['3613'].processed.connections), {x for x in ['2997']})
            self.assertEqual(set(dataset.certs['2721'].processed.connections), {x for x in ['2441', '2711']})
            self.assertEqual(set(dataset.certs['2798'].processed.connections), {x for x in ['2721', '2711']})
            self.assertEqual(set(dataset.certs['2711'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['2997'].processed.connections), {x for x in ['2711']})
            self.assertEqual(set(dataset.certs['2742'].processed.connections), {x for x in ['2721', '2711']})
            self.assertEqual(set(dataset.certs['2721'].processed.connections), {x for x in ['2441', '2711']})

    def test_docusign_chunk(self):
        certs = self.certs_to_parse[4]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)
            self.assertEqual(set(dataset.certs['3850'].processed.connections), {x for x in ['3518', '1883']})
            self.assertEqual(set(dataset.certs['2779'].processed.connections), {x for x in ['1883']})
            self.assertEqual(set(dataset.certs['2860'].processed.connections), {x for x in ['1883']})
            self.assertEqual(set(dataset.certs['2665'].processed.connections), {x for x in ['1883']})
            self.assertEqual(set(dataset.certs['1883'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['3518'].processed.connections), {x for x in ['1883']})
            self.assertEqual(set(dataset.certs['3141'].processed.connections), {x for x in ['1883']})
            self.assertEqual(set(dataset.certs['2590'].processed.connections), {x for x in ['1883']})

    def test_openssl_chunk(self):
        certs = self.certs_to_parse[5]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)
            self.assertEqual(set(dataset.certs['3493'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['3495'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['3711'].processed.connections), {x for x in ['3220']})
            self.assertEqual(set(dataset.certs['3176'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['3488'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['3126'].processed.connections), {x for x in ['3126', '2398']})
            self.assertEqual(set(dataset.certs['3269'].processed.connections), {x for x in ['3269', '3220']})
            self.assertEqual(set(dataset.certs['3524'].processed.connections), {x for x in ['3220']})
            self.assertEqual(set(dataset.certs['3220'].processed.connections), {x for x in ['3220', '2398']})
            self.assertEqual(set(dataset.certs['2398'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['3543'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['2676'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['3313'].processed.connections), {x for x in ['3313', '3220']})
            self.assertEqual(set(dataset.certs['3363'].processed.connections), {x for x in []})
            self.assertEqual(set(dataset.certs['3608'].processed.connections), {x for x in ['2398']})
            self.assertEqual(set(dataset.certs['3158'].processed.connections), {x for x in ['2398']})
