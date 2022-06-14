from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile
from typing import Final, List, Optional, Set, Tuple, Union

import numpy as np
import pandas as pd
from tqdm.notebook import tqdm

from sec_certs import helpers
from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.sar import SAR


@dataclass(eq=True, frozen=True)
class SecondarySFPCluster:
    name: str
    children: frozenset[int]

    @classmethod
    def from_xml_id(cls, xml_categories: List[ET.Element], cwe_id: int):
        cat = cls.find_correct_category(xml_categories, cwe_id)
        name = cat.attrib["Name"]
        members = cat.find("{http://cwe.mitre.org/cwe-6}Relationships")

        assert members is not None
        member_ids = frozenset(
            (int(x.attrib["CWE_ID"]) for x in members if x.tag == "{http://cwe.mitre.org/cwe-6}Has_Member")
        )
        return cls(name, member_ids)

    @staticmethod
    def find_correct_category(xml_categories: List[ET.Element], cwe_id: int) -> ET.Element:
        for cat in xml_categories:
            if cat.attrib["ID"] == str(cwe_id):
                return cat
        raise ValueError(f"Category with ID {cwe_id} found.")


@dataclass(eq=True, frozen=True)
class PrimarySFPCluster:
    name: str
    secondary_clusters: frozenset[SecondarySFPCluster]
    cwe_ids: frozenset[int]

    @classmethod
    def from_xml(cls, xml_categories: List[ET.Element], primary_cluster_element: ET.Element):
        name = primary_cluster_element.attrib["Name"].split("SFP Primary Cluster: ")[1]
        members = primary_cluster_element.find("{http://cwe.mitre.org/cwe-6}Relationships")

        assert members is not None
        member_ids = {int(x.attrib["CWE_ID"]) for x in members if x.tag == "{http://cwe.mitre.org/cwe-6}Has_Member"}

        secondary_clusters = []
        cwe_ids = []
        for member_id in member_ids:
            try:
                secondary_clusters.append(SecondarySFPCluster.from_xml_id(xml_categories, member_id))
            except ValueError:
                cwe_ids.append(member_id)

        return cls(name, frozenset(secondary_clusters), frozenset(cwe_ids))


class SFPModel:
    URL: Final[str] = "https://cwe.mitre.org/data/xml/views/888.xml.zip"
    XML_FILENAME: Final[str] = "888.xml"
    XML_ZIP_NAME: Final[str] = "888.xml.zip"

    def __init__(self, primary_clusters: frozenset[PrimarySFPCluster]):
        self.primary_clusters = primary_clusters

    @classmethod
    def from_xml(cls, xml_filepath: Union[str, Path]):
        tree = ET.parse(xml_filepath)
        category_tag = tree.getroot().find("{http://cwe.mitre.org/cwe-6}Categories")

        assert category_tag is not None
        categories = category_tag.findall("{http://cwe.mitre.org/cwe-6}Category")

        # The XML contains two weird primary clusters not specified in https://samate.nist.gov/BF/Enlightenment/SFP.html.
        # After manual inspection, we skip those
        primary_clusters = frozenset(
            (
                PrimarySFPCluster.from_xml(categories, x)
                for x in categories
                if (
                    "SFP Primary Cluster" in x.attrib["Name"]
                    and x.attrib["Name"] != "SFP Primary Cluster: Failure to Release Memory"
                    and x.attrib["Name"] != "SFP Primary Cluster: Faulty Resource Release"
                )
            )
        )

        return cls(primary_clusters)

    @classmethod
    def from_web(cls):
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_zip_path = Path(tmp_dir) / cls.XML_ZIP_NAME
            helpers.download_file(cls.URL, xml_zip_path)

            with zipfile.ZipFile(xml_zip_path, "r") as zip_handle:
                zip_handle.extractall(tmp_dir)

            return cls.from_xml(Path(tmp_dir) / cls.XML_FILENAME)

    def search_cwe(self, cwe_id: int) -> Tuple[Optional[str], Optional[str]]:
        for primary in self.primary_clusters:
            for secondary in primary.secondary_clusters:
                if cwe_id in secondary.children:
                    return primary.name, secondary.name
            if cwe_id in primary.cwe_ids:
                return primary.name, None
        return None, None


def discover_sar_families(ser: pd.Series) -> List[str]:
    """
    Returns a list of all SAR families that occur in the pandas Series, where each entry is a set of SAR objects.
    """
    sars = ser.tolist()
    families = set()
    for cert in sars:
        families |= {x.family for x in cert} if not pd.isnull(cert) else set()
    return list(families)


def get_sar_level_from_set(sars: Set[SAR], sar_family: str) -> Optional[int]:
    """
    Given a set of SARs and a family name, will return level of the seeked SAR from the set.
    """
    family_sars_dict = {x.family: x for x in sars} if (sars and not pd.isnull(sars)) else dict()
    if sar_family not in family_sars_dict.keys():
        return None
    return family_sars_dict[sar_family].level


def compute_cve_correlations(
    df: pd.DataFrame,
    exclude_vuln_free_certs: bool = False,
    output_path: Optional[Union[str, Path]] = None,
    filter_nans: bool = True,
) -> pd.DataFrame:
    """
    Computes correlations of EAL and different SARs and two columns: (n_cves, worst_cve_score, avg_cve_score). Few assumptions about the passed dataframe:
    - EAL column must be categorical data type
    - SAR column must be a set of SARs
    - `n_cves` and `worst_cve_score`, `avg_cve_score` columns must be present in the dataframe
    Possibly, it can filter columns will both values NaN (due to division by zero or super low supports.)
    """
    df_sar = df.loc[:, ["eal", "extracted_sars", "worst_cve_score", "avg_cve_score", "n_cves"]]
    families = discover_sar_families(df_sar.extracted_sars)
    df_sar.eal = df_sar.eal.cat.codes

    if exclude_vuln_free_certs:
        df_sar = df_sar.loc[df_sar.n_cves > 0]

    n_cves_corrs = [df_sar["eal"].corr(df_sar.n_cves)]
    worst_cve_corrs = [df_sar["eal"].corr(df_sar.worst_cve_score)]
    avg_cve_corrs = [df_sar["eal"].corr(df_sar.avg_cve_score)]
    supports = [df_sar.loc[~df_sar["eal"].isnull()].shape[0]]

    for family in tqdm(families):
        df_sar[family] = df_sar.extracted_sars.map(lambda x: get_sar_level_from_set(x, family))
        n_cves_corrs.append(df_sar[family].corr(df_sar.n_cves))
        worst_cve_corrs.append(df_sar[family].corr(df_sar.worst_cve_score))
        avg_cve_corrs.append(df_sar[family].corr(df_sar.avg_cve_score))
        supports.append(df_sar.loc[~df_sar[family].isnull()].shape[0])
    df_sar = df_sar.copy()

    tuples = list(zip(n_cves_corrs, worst_cve_corrs, avg_cve_corrs, supports))
    dct = {family: correlations for family, correlations in zip(["eal"] + families, tuples)}
    df_corr = pd.DataFrame.from_dict(
        dct, orient="index", columns=["n_cves_corr", "worst_cve_score_corr", "avg_cve_score_corr", "support"]
    )
    df_corr.style.set_caption("Correlations between EAL, SARs and CVEs")
    df_corr = df_corr.sort_values(by="support", ascending=False)

    if filter_nans:
        df_corr = df_corr.dropna(how="all", subset=["n_cves_corr", "worst_cve_score_corr", "avg_cve_score_corr"])

    if output_path:
        df_corr.to_csv(output_path)

    return df_corr


def find_earliest_maintenance_after_cve(row):
    "Given dataframe row, will return first maintenance date succeeding first published CVE related to a certificate if exists, else np.nan"
    if isinstance(row["earliest_cve"], float):
        return np.nan
    maintenances_after_cve = list(filter(lambda x: x > row["earliest_cve"], row["maintenance_dates"]))
    return min(maintenances_after_cve) if maintenances_after_cve else np.nan


def expand_cc_df_with_cve_cols(cc_df: pd.DataFrame, cve_dset: CVEDataset) -> pd.DataFrame:
    df = cc_df.copy()
    df["n_cves"] = df.related_cves.map(lambda x: len(x) if x is not np.nan else 0)
    df["cve_published_dates"] = df.related_cves.map(
        lambda x: [cve_dset[y].published_date.date() for y in x] if x is not np.nan else np.nan  # type: ignore
    )
    df["earliest_cve"] = df.cve_published_dates.map(lambda x: min(x) if isinstance(x, list) else np.nan)
    df["worst_cve_score"] = df.related_cves.map(
        lambda x: max([cve_dset[cve].impact.base_score for cve in x]) if x is not np.nan else np.nan
    )

    """
    Note: Technically, CVE can have 0 base score. This happens when the CVE is discarded from the database.
    This could skew the results. During May 2022 analysis, we encountered a single CVE with such score.
    Therefore, we do not treat this case.
    To properly treat this, the average should be taken across CVEs with >0 base_socre.
    """
    df["avg_cve_score"] = df.related_cves.map(
        lambda x: np.mean([cve_dset[cve].impact.base_score for cve in x]) if x is not np.nan else np.nan
    )
    return df


def prepare_cwe_df(cc_df: pd.DataFrame, cve_dset: CVEDataset) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    This function does the following:
    1. Filter CC DF to columns relevant for CWE examination (eal, related_cves, category)
    2. Parses CWE webpage of CWE categories and weaknesses, fetches CWE descriptions and names from there
    3. Explodes the CC DF so that each row corresponds to single CVE
    4. Joins CC DF with CWE DF obtained from CVEDataset
    5. Explodes resulting DF again so that each row corresponds to single CWE

    :param pd.DataFrame cc_df: DataFrame obtained from CCDataset, should be limited to rows with >0 vulnerabilities
    :param CVEDataset cve_dset: CVEDataset instance to retrieve CWE data from
    :return Tuple[pd.DataFrame, pd.DataFrame]: returns two dataframes:
        - DF obtained from CC Dataset, fully exploded to CWEs
        - DF obtained from CWE webpage, contains IDs, names, types, urls of all CWEs
    """
    # Explode CVE_IDs and CWE_IDs so that we have right counts on duplicated CVEs. Measure how much data for analysis we have left.
    vulns = cve_dset.to_pandas()
    df_cwe_relevant = (
        cc_df[["eal", "related_cves", "category"]]
        .explode(column="related_cves")
        .rename(columns={"related_cves": "cve_id"})
    )
    df_cwe_relevant["cwe_ids"] = df_cwe_relevant.cve_id.map(lambda x: vulns.cwe_ids[x])
    df_cwe_relevant = (
        df_cwe_relevant.explode(column="cwe_ids")
        .reset_index()
        .rename(columns={"cwe_ids": "cwe_id", "index": "cert_dgst"})
    )

    df_cwe_relevant.cwe_id = df_cwe_relevant.cwe_id.replace(r"NVD-CWE-*", np.nan, regex=True)
    print(
        f"Filtering {df_cwe_relevant.loc[df_cwe_relevant.cwe_id.isna(), 'cve_id'].nunique()} CVEs that have no CWE assigned. This affects {df_cwe_relevant.loc[df_cwe_relevant.cwe_id.isna(), 'cert_dgst'].nunique()} certificates"
    )
    print(
        f"Still left with analysis of {df_cwe_relevant.loc[~df_cwe_relevant.cwe_id.isna(), 'cve_id'].nunique()} CVEs in {df_cwe_relevant.loc[~df_cwe_relevant.cwe_id.isna(), 'cert_dgst'].nunique()} certificates."
    )
    df_cwe_relevant = df_cwe_relevant.dropna()

    # Load CWE IDs and descriptions from CWE website
    with tempfile.TemporaryDirectory() as tmp_dir:
        xml_zip_path = Path(tmp_dir) / "cwec_latest.xml.zip"
        helpers.download_file("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", xml_zip_path)

        with zipfile.ZipFile(xml_zip_path, "r") as zip_handle:
            zip_handle.extractall(tmp_dir)
            xml_filename = zip_handle.namelist()[0]

        root = ET.parse(Path(tmp_dir) / xml_filename).getroot()

    weaknesses = root.find("{http://cwe.mitre.org/cwe-6}Weaknesses")
    categories = root.find("{http://cwe.mitre.org/cwe-6}Categories")
    dct: dict[str, List[Optional[str]]] = {"cwe_id": [], "cwe_name": [], "cwe_description": [], "type": []}

    assert weaknesses
    for weakness in weaknesses:
        assert weakness
        description = weakness.find("{http://cwe.mitre.org/cwe-6}Description")
        assert description

        dct["cwe_id"].append("CWE-" + weakness.attrib["ID"])
        dct["cwe_name"].append(weakness.attrib["Name"])
        dct["cwe_description"].append(description.text)
        dct["type"].append("weakness")

    assert categories
    for category in categories:
        assert category
        summary = category.find("{http://cwe.mitre.org/cwe-6}Summary")
        assert summary

        dct["cwe_id"].append("CWE-" + category.attrib["ID"])
        dct["cwe_name"].append(category.attrib["Name"])
        dct["cwe_description"].append(summary.text)
        dct["type"].append("category")

    cwe_df = pd.DataFrame(dct).set_index("cwe_id")
    cwe_df["url"] = cwe_df.index.map(lambda x: "https://cwe.mitre.org/data/definitions/" + x.split("-")[1] + ".html")
    cwe_df = cwe_df.replace(r"\n", " ", regex=True)

    return df_cwe_relevant, cwe_df


def compute_maintenances_that_should_fix_vulns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Given pre-processed CCDataset DataFrame (expanded with MU & CVE cols), computes time to fix CVE and earliest CVE after some vuln.
    """
    df_fixed = df.loc[(df.n_cves > 0) & (df.n_maintenances > 0)].copy()
    df_fixed.maintenance_dates = df_fixed.maintenance_dates.map(
        lambda x: [y.date() for y in x] if not isinstance(x, float) else x
    )
    df_fixed.loc[:, "earliest_maintenance"] = df_fixed.apply(find_earliest_maintenance_after_cve, axis=1)
    df_fixed.loc[:, "time_to_fix_cve"] = df_fixed.earliest_maintenance - df_fixed.earliest_cve
    df_fixed.index.name = "dgst"
    return df_fixed


def move_fixing_mu_to_directory(
    df_fixed: pd.DataFrame, main_df: pd.DataFrame, outdir: Union[str, Path], inpath: Union[str, Path]
) -> pd.DataFrame:
    """
    Localizes reports of maintenance updates that should fix some vulnerability and copies them into a directory.
    df_fixed should be the output of compute_maintenances_that_should_fix_vulns method.
    """
    fixed_df_index = (
        df_fixed.loc[~df_fixed.earliest_maintenance.isnull()]
        .reset_index()
        .set_index(["dgst", "earliest_maintenance"])
        .index.to_flat_index()
    )
    main_df.maintenance_date = main_df.maintenance_date.map(lambda x: x.date())
    main_prefiltered = main_df.reset_index().set_index(["related_cert_digest", "maintenance_date"])
    mu_filenames = main_prefiltered.loc[main_prefiltered.index.isin(fixed_df_index), "dgst"]
    mu_filenames = mu_filenames.map(lambda x: x + ".pdf")

    inpath = Path(inpath)
    if not inpath.exists():
        inpath.mkdir()

    for i in mu_filenames:
        copyfile(inpath / i, Path(outdir) / i)

    return mu_filenames
