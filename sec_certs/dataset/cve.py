import datetime
import glob
import itertools
import json
import logging
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Final, List, Optional, Set, Union

import pandas as pd

import sec_certs.constants as constants
import sec_certs.helpers as helpers
from sec_certs.config.configuration import config
from sec_certs.parallel_processing import process_parallel
from sec_certs.sample.cpe import CPE, cached_cpe
from sec_certs.sample.cve import CVE
from sec_certs.serialization.json import ComplexSerializableType, CustomJSONDecoder, CustomJSONEncoder

logger = logging.getLogger(__name__)


@dataclass
class CVEDataset(ComplexSerializableType):
    cves: Dict[str, CVE]
    cpe_to_cve_ids_lookup: Dict[str, Set[str]] = field(init=False)
    cve_url: Final[str] = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
    cpe_match_feed_url: Final[str] = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip"

    @property
    def serialized_attributes(self) -> List[str]:
        return ["cves"]

    def __iter__(self):
        yield from self.cves.values()

    def __getitem__(self, item: str) -> CVE:
        return self.cves.__getitem__(item.upper())

    def __setitem__(self, key: str, value: CVE):
        self.cves.__setitem__(key.lower(), value)

    def __len__(self) -> int:
        return len(self.cves)

    def __eq__(self, other: object):
        return isinstance(other, CVEDataset) and self.cves == other.cves

    def build_lookup_dict(self, use_nist_mapping: bool = True, nist_matching_filepath: Optional[Path] = None):
        """
        Builds look-up dictionary CPE -> Set[CVE]
        Developer's note: There are 3 CPEs that are present in the cpe matching feed, but are badly processed by CVE
        feed, in which case they won't be found as a key in the dictionary. We intentionally ignore those. Feel free
        to add corner cases and manual fixes. According to our investigation, the suffereing CPEs are:
            - CPE(uri='cpe:2.3:a:arubanetworks:airwave:*:*:*:*:*:*:*:*', title=None, version='*', vendor='arubanetworks', item_name='airwave', start_version=None, end_version=('excluding', '8.2.0.0'))
            - CPE(uri='cpe:2.3:a:bayashi:dopvcomet\\*:0009:b:*:*:*:*:*:*', title=None, version='0009', vendor='bayashi', item_name='dopvcomet\\*', start_version=None, end_version=None)
            - CPE(uri='cpe:2.3:a:bayashi:dopvstar\\*:0091:*:*:*:*:*:*:*', title=None, version='0091', vendor='bayashi', item_name='dopvstar\\*', start_version=None, end_version=None)
        """
        self.cpe_to_cve_ids_lookup = dict()
        self.cves = {x.cve_id.upper(): x for x in self}

        logger.info("Getting CPE matching dictionary from NIST.gov")

        if use_nist_mapping:
            matching_dict = self.get_nist_cpe_matching_dict(nist_matching_filepath)

        cve: CVE
        for cve in helpers.tqdm(self, desc="Building-up lookup dictionaries for fast CVE matching"):
            # See note above, we use matching_dict.get(cpe, []) instead of matching_dict[cpe] as would be expected
            if use_nist_mapping:
                vulnerable_configurations = list(
                    itertools.chain.from_iterable([matching_dict.get(cpe, []) for cpe in cve.vulnerable_cpes])
                )
            else:
                vulnerable_configurations = cve.vulnerable_cpes
            for cpe in vulnerable_configurations:
                if cpe.uri not in self.cpe_to_cve_ids_lookup:
                    self.cpe_to_cve_ids_lookup[cpe.uri] = {cve.cve_id}
                else:
                    self.cpe_to_cve_ids_lookup[cpe.uri].add(cve.cve_id)

    @classmethod
    def download_cves(cls, output_path_str: str, start_year: int, end_year: int):
        output_path = Path(output_path_str)
        if not output_path.exists:
            output_path.mkdir()

        urls = [cls.cve_url + str(x) + ".json.zip" for x in range(start_year, end_year + 1)]

        logger.info(f"Identified {len(urls)} CVE files to fetch from nist.gov. Downloading them into {output_path}")
        with tempfile.TemporaryDirectory() as tmp_dir:
            outpaths = [Path(tmp_dir) / Path(x).name.rstrip(".zip") for x in urls]
            responses = list(zip(*helpers.download_parallel(list(zip(urls, outpaths)), num_threads=config.n_threads)))[
                1
            ]

            for o, u, r in zip(outpaths, urls, responses):
                if r == constants.RESPONSE_OK:
                    with zipfile.ZipFile(o, "r") as zip_handle:
                        zip_handle.extractall(output_path)
                else:
                    logger.info(f"Failed to download from {u}, got status code {r}")

    @classmethod
    def from_nist_json(cls, input_path: str) -> "CVEDataset":
        with Path(input_path).open("r") as handle:
            data = json.load(handle)
        cves = [CVE.from_nist_dict(x) for x in data["CVE_Items"]]
        return cls({x.cve_id: x for x in cves})

    @classmethod
    def from_web(cls, start_year: int = 2002, end_year: int = datetime.datetime.now().year):
        logger.info("Building CVE dataset from nist.gov website.")
        with tempfile.TemporaryDirectory() as tmp_dir:
            cls.download_cves(tmp_dir, start_year, end_year)
            json_files = glob.glob(tmp_dir + "/*.json")

            all_cves = dict()
            logger.info("Downloaded required resources. Building CVEDataset from jsons.")
            results = process_parallel(
                cls.from_nist_json,
                json_files,
                config.n_threads,
                use_threading=False,
                progress_bar_desc="Building CVEDataset from jsons",
            )
            for r in results:
                all_cves.update(r.cves)

        return cls(all_cves)

    def to_json(self, output_path: Optional[Union[str, Path]] = None):
        if output_path is None:
            raise RuntimeError(
                f"You tried to serialize an object ({type(self)}) that does not have implicit json path. Please provide json_path."
            )
        with Path(output_path).open("w") as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        with Path(input_path).open("r") as handle:
            dset = json.load(handle, cls=CustomJSONDecoder)
        return dset

    def get_cve_ids_for_cpe_uri(self, cpe_uri: str) -> Optional[Set[str]]:
        return self.cpe_to_cve_ids_lookup.get(cpe_uri, None)

    def filter_related_cpes(self, relevant_cpes: Set[CPE]):
        """
        Since each of the CVEs is related to many CPEs, the dataset size explodes (serialized). For certificates,
        only CPEs within sample dataset are relevant. This function modifies all CVE elements. Specifically, it
        deletes all CPE records unless they are part of relevant_cpe_uris.
        :param relevant_cpes: List of relevant CPEs to keep in CVE dataset.
        """
        total_deleted_cpes = 0
        cve_ids_to_delete = []
        for cve in self:
            n_cpes_orig = len(cve.vulnerable_cpes)
            cve.vulnerable_cpes = list(filter(lambda x: x in relevant_cpes, cve.vulnerable_cpes))
            total_deleted_cpes += n_cpes_orig - len(cve.vulnerable_cpes)
            if not cve.vulnerable_cpes:
                cve_ids_to_delete.append(cve.cve_id)

        for cve_id in cve_ids_to_delete:
            del self.cves[cve_id]
        logger.info(
            f"Totally deleted {total_deleted_cpes} irrelevant CPEs and {len(cve_ids_to_delete)} CVEs from CVEDataset."
        )

    def to_pandas(self) -> pd.DataFrame:
        df = pd.DataFrame([x.pandas_tuple for x in self], columns=CVE.pandas_columns)
        return df.set_index("cve_id")

    def get_nist_cpe_matching_dict(self, input_filepath: Optional[Path]) -> Dict[CPE, List[CPE]]:
        """
        Computes dictionary that maps complex CPEs to list of simple CPEs.
        """

        def parse_key_cpe(field: Dict) -> CPE:
            start_version = None
            if "versionStartIncluding" in field:
                start_version = ("including", field["versionStartIncluding"])
            elif "versionStartExcluding" in field:
                start_version = ("excluding", field["versionStartExcluding"])

            end_version = None
            if "versionEndIncluding" in field:
                end_version = ("including", field["versionEndIncluding"])
            elif "versionEndExcluding" in field:
                end_version = ("excluding", field["versionEndExcluding"])

            return cached_cpe(field["cpe23Uri"], start_version=start_version, end_version=end_version)

        def parse_values_cpe(field: Dict) -> List[CPE]:
            return [cached_cpe(x["cpe23Uri"]) for x in field["cpe_name"]]

        logger.debug("Attempting to get NIST mapping file.")
        if not input_filepath or not input_filepath.is_file():
            logger.debug("NIST mapping file not available, going to download.")
            with tempfile.TemporaryDirectory() as tmp_dir:
                filename = Path(self.cpe_match_feed_url).name
                download_path = Path(tmp_dir) / filename
                unzipped_path = Path(tmp_dir) / filename.rstrip(".zip")
                helpers.download_file(self.cpe_match_feed_url, download_path)

                with zipfile.ZipFile(download_path, "r") as zip_handle:
                    zip_handle.extractall(tmp_dir)
                with unzipped_path.open("r") as handle:
                    match_data = json.load(handle)
                if input_filepath:
                    logger.debug(f"Copying attained NIST mapping file to {input_filepath}")
                    shutil.move(str(unzipped_path), str(input_filepath))
        else:
            with input_filepath.open("r") as handle:
                match_data = json.load(handle)

        mapping_dict = dict()
        for match in helpers.tqdm(match_data["matches"], desc="parsing cpe matching (by NIST) dictionary"):
            key = parse_key_cpe(match)
            value = parse_values_cpe(match)
            mapping_dict[key] = value if value else [key]

        return mapping_dict
