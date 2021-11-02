from unittest import TestCase
from pathlib import Path
from tempfile import TemporaryDirectory

from sec_certs.dataset.fips import FIPSDataset
from sec_certs.dataset.fips_algorithm import FIPSAlgorithmDataset
from sec_certs.config.configuration import config
from tests.fips_test_utils import generate_html


def _set_up_dataset(td, certs):
    dataset = FIPSDataset({}, Path(td), 'test_dataset', 'fips_test_dataset')
    generate_html(certs, td + '/test_search.html')
    dataset.get_certs_from_web(test=td + '/test_search.html', no_download_algorithms=True)
    return dataset


def _set_up_dataset_for_full(td, certs):
    dataset = _set_up_dataset(td, certs)
    dataset.web_scan()
    dataset.convert_all_pdfs()
    dataset.pdf_scan()
    dataset.extract_certs_from_tables(high_precision=True)
    dataset.algorithms = FIPSAlgorithmDataset.from_json(Path(__file__).parent / 'data/test_fips_oop/algorithms.json')
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
        config.load(Path(__file__).parent / 'settings_test.yaml')

    def test_size(self):
        for certs in self.certs_to_parse:
            with TemporaryDirectory() as td:
                dataset = _set_up_dataset(td, certs)
                self.assertEqual(len(dataset.certs), len(certs), "Wrong number of parsed certs")

    def test_connections_microsoft(self):
        certs = self.certs_to_parse[2]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)

            self.assertEqual(set(dataset.certs['3095'].heuristics.connections), {'3093', '3096', '3094'})
            self.assertEqual(set(dataset.certs['3651'].heuristics.connections), {'3615'})
            self.assertEqual(set(dataset.certs['3093'].heuristics.connections), {'3090', '3091'})
            self.assertEqual(set(dataset.certs['3090'].heuristics.connections), {'3089'})
            self.assertEqual(set(dataset.certs['3197'].heuristics.connections),
                             {x for x in ['3195', '3096', '3196', '3644', '3651']})
            self.assertEqual(set(dataset.certs['3196'].heuristics.connections),
                             {x for x in ['3194', '3091', '3480', '3615']})
            self.assertEqual(set(dataset.certs['3089'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['3195'].heuristics.connections), {'3194', '3091', '3480'})
            self.assertEqual(set(dataset.certs['3480'].heuristics.connections), {'3089'})
            self.assertEqual(set(dataset.certs['3615'].heuristics.connections), {'3089'})
            self.assertEqual(set(dataset.certs['3194'].heuristics.connections), {'3089'})
            self.assertEqual(set(dataset.certs['3091'].heuristics.connections), {'3089'})
            self.assertEqual(set(dataset.certs['3690'].heuristics.connections), {'3644', '3196', '3651'})
            self.assertEqual(set(dataset.certs['3644'].heuristics.connections), {'3615'})
            self.assertEqual(set(dataset.certs['3527'].heuristics.connections), {'3090', '3091'})
            self.assertEqual(set(dataset.certs['3094'].heuristics.connections), {'3090', '3091'})
            self.assertEqual(set(dataset.certs['3544'].heuristics.connections), {'3093', '3096', '3527'})
            self.assertEqual(set(dataset.certs['3096'].heuristics.connections), {'3090', '3194', '3091', '3480'})
            self.assertEqual(set(dataset.certs['3092'].heuristics.connections), {'3093', '3195', '3096', '3644', '3651'})

    def test_connections_redhat(self):
        certs = self.certs_to_parse[3]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)
            self.assertEqual(set(dataset.certs['2630'].heuristics.connections), {'2441'})
            self.assertEqual(set(dataset.certs['2633'].heuristics.connections), {'2441'})
            self.assertEqual(set(dataset.certs['2441'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['2997'].heuristics.connections), {'2711'})
            self.assertEqual(set(dataset.certs['2446'].heuristics.connections), {'2441'})
            self.assertEqual(set(dataset.certs['2447'].heuristics.connections), {'2441'})
            self.assertEqual(set(dataset.certs['3733'].heuristics.connections), {'2441'})
            self.assertEqual(set(dataset.certs['2441'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['2711'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['2908'].heuristics.connections), {'2711'})
            self.assertEqual(set(dataset.certs['3613'].heuristics.connections), {'2997'})
            self.assertEqual(set(dataset.certs['2721'].heuristics.connections), {'2441', '2711'})
            self.assertEqual(set(dataset.certs['2798'].heuristics.connections), {'2721', '2711'})
            self.assertEqual(set(dataset.certs['2711'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['2997'].heuristics.connections), {'2711'})
            self.assertEqual(set(dataset.certs['2742'].heuristics.connections), {'2721', '2711'})
            self.assertEqual(set(dataset.certs['2721'].heuristics.connections), {'2441', '2711'})

    def test_docusign_chunk(self):
        certs = self.certs_to_parse[4]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)
            self.assertEqual(set(dataset.certs['3850'].heuristics.connections), {'3518', '1883'})
            self.assertEqual(set(dataset.certs['2779'].heuristics.connections), {'1883'})
            self.assertEqual(set(dataset.certs['2860'].heuristics.connections), {'1883'})
            self.assertEqual(set(dataset.certs['2665'].heuristics.connections), {'1883'})
            self.assertEqual(set(dataset.certs['1883'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['3518'].heuristics.connections), {'1883'})
            self.assertEqual(set(dataset.certs['3141'].heuristics.connections), {'1883'})
            self.assertEqual(set(dataset.certs['2590'].heuristics.connections), {'1883'})

    def test_openssl_chunk(self):
        certs = self.certs_to_parse[5]
        with TemporaryDirectory() as td:
            dataset = _set_up_dataset_for_full(td, certs)
            self.assertEqual(set(dataset.certs['3493'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['3495'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['3711'].heuristics.connections), {'3220'})
            self.assertEqual(set(dataset.certs['3176'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['3488'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['3126'].heuristics.connections), {'3126', '2398'})
            self.assertEqual(set(dataset.certs['3269'].heuristics.connections), {'3269', '3220'})
            self.assertEqual(set(dataset.certs['3524'].heuristics.connections), {'3220'})
            self.assertEqual(set(dataset.certs['3220'].heuristics.connections), {'3220', '2398'})
            self.assertEqual(set(dataset.certs['2398'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['3543'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['2676'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['3313'].heuristics.connections), {'3313', '3220'})
            self.assertEqual(set(dataset.certs['3363'].heuristics.connections), set())
            self.assertEqual(set(dataset.certs['3608'].heuristics.connections), {'2398'})
            self.assertEqual(set(dataset.certs['3158'].heuristics.connections), {'2398'})
