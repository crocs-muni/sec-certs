from __future__ import annotations

import copy
import functools
import logging
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile
from typing import Any, Final

import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from scipy import stats
from tqdm.notebook import tqdm

from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.sar import SAR
from sec_certs.utils import helpers

logger = logging.getLogger(__name__)


@dataclass(eq=True, frozen=True)
class SecondarySFPCluster:
    name: str
    children: frozenset[int]

    @classmethod
    def from_xml_id(cls, xml_categories: list[ET.Element], cwe_id: int):
        cat = cls.find_correct_category(xml_categories, cwe_id)
        name = cat.attrib["Name"]
        members = cat.find("{http://cwe.mitre.org/cwe-6}Relationships")

        assert members is not None
        member_ids = frozenset(
            int(x.attrib["CWE_ID"]) for x in members if x.tag == "{http://cwe.mitre.org/cwe-6}Has_Member"
        )
        return cls(name, member_ids)

    @staticmethod
    def find_correct_category(xml_categories: list[ET.Element], cwe_id: int) -> ET.Element:
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
    def from_xml(cls, xml_categories: list[ET.Element], primary_cluster_element: ET.Element):
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
    def from_xml(cls, xml_filepath: str | Path):
        tree = ET.parse(xml_filepath)
        category_tag = tree.getroot().find("{http://cwe.mitre.org/cwe-6}Categories")

        assert category_tag is not None
        categories = category_tag.findall("{http://cwe.mitre.org/cwe-6}Category")

        # The XML contains two weird primary clusters not specified in https://samate.nist.gov/BF/Enlightenment/SFP.html.
        # After manual inspection, we skip those
        primary_clusters = frozenset(
            PrimarySFPCluster.from_xml(categories, x)
            for x in categories
            if (
                "SFP Primary Cluster" in x.attrib["Name"]
                and x.attrib["Name"] != "SFP Primary Cluster: Failure to Release Memory"
                and x.attrib["Name"] != "SFP Primary Cluster: Faulty Resource Release"
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

    def search_cwe(self, cwe_id: int) -> tuple[str | None, str | None]:
        for primary in self.primary_clusters:
            for secondary in primary.secondary_clusters:
                if cwe_id in secondary.children:
                    return primary.name, secondary.name
            if cwe_id in primary.cwe_ids:
                return primary.name, None
        return None, None


def discover_sar_families(ser: pd.Series) -> list[str]:
    """
    Returns a list of all SAR families that occur in the pandas Series, where each entry is a set of SAR objects.
    """
    sars = ser.tolist()
    families = set()
    for cert in sars:
        families |= {x.family for x in cert} if not pd.isnull(cert) else set()
    return list(families)


def get_sar_level_from_set(sars: set[SAR], sar_family: str) -> int | None:
    """
    Given a set of SARs and a family name, will return level of the seeked SAR from the set.
    """
    family_sars_dict = {x.family: x for x in sars} if (sars and not pd.isnull(sars)) else {}
    if sar_family not in family_sars_dict:
        return None
    return family_sars_dict[sar_family].level


def compute_cve_correlations(
    df: pd.DataFrame,
    exclude_vuln_free_certs: bool = False,
    sar_families: list[str] | None = None,
    output_path: str | Path | None = None,
    filter_nans: bool = True,
) -> pd.DataFrame:
    """
    Computes correlations of EAL and different SARs and two columns: (n_cves, worst_cve_score, avg_cve_score). Few assumptions about the passed dataframe:
    - EAL column must be categorical data type
    - SAR column must be a set of SARs
    - `n_cves` and `worst_cve_score`, `avg_cve_score` columns must be present in the dataframe
    Possibly, it can filter columns will both values NaN (due to division by zero or super low supports.)
    To choose correct minimal support is tricky, this is because SAR levels often having huge support, but being imbalanced themselves heavily in the favor
    of a single value that is rarely modified. We recommend choosing 100 and discarding any row where some column would result into NaN
    """
    df_sar = df.loc[:, ["eal", "extracted_sars", "worst_cve_score", "avg_cve_score", "n_cves", "category"]]
    df_sar = df_sar.loc[df_sar.category != "ICs, Smart Cards and Smart Card-Related Devices and Systems"]

    if exclude_vuln_free_certs:
        df_sar = df_sar.loc[df_sar.n_cves > 0]

    families = sar_families if sar_families else discover_sar_families(df_sar.extracted_sars)

    spearmanr = functools.partial(stats.spearmanr, nan_policy="omit", alternative="less")

    df_sar.eal = df_sar.eal.cat.codes
    df_sar.eal = df_sar.eal.map(lambda x: np.NaN if x == -1 else x)

    n_cves_eal_corr, n_cves_eal_pvalue = spearmanr(df_sar.eal, df_sar.n_cves)
    n_cves_corrs = [n_cves_eal_corr]
    n_cves_pvalues = [n_cves_eal_pvalue]

    worst_cve_eal_corr, worst_cve_eal_pvalue = spearmanr(df_sar.eal, df_sar.worst_cve_score)
    worst_cve_corrs = [worst_cve_eal_corr]
    worst_cve_pvalues = [worst_cve_eal_pvalue]

    avg_cve_eal_corr, avg_cve_eal_pvalue = spearmanr(df_sar.eal, df_sar.avg_cve_score)
    avg_cve_corrs = [avg_cve_eal_corr]
    avg_cve_pvalues = [avg_cve_eal_pvalue]

    supports = [df_sar.loc[~df_sar["eal"].isnull()].shape[0]]

    for family in tqdm(families):
        df_sar[family] = df_sar.extracted_sars.map(lambda x: get_sar_level_from_set(x, family))

        n_cves_corr, n_cves_pvalue = spearmanr(df_sar[family], df_sar.n_cves)
        n_cves_corrs.append(n_cves_corr)
        n_cves_pvalues.append(n_cves_pvalue)

        worst_cve_corr, worst_cve_pvalue = spearmanr(df_sar[family], df_sar.worst_cve_score)
        worst_cve_corrs.append(worst_cve_corr)
        worst_cve_pvalues.append(worst_cve_pvalue)

        avg_cve_corr, avg_cve_pvalue = spearmanr(df_sar[family], df_sar.avg_cve_score)
        avg_cve_corrs.append(avg_cve_corr)
        avg_cve_pvalues.append(avg_cve_pvalue)

        supports.append(df_sar.loc[~df_sar[family].isnull()].shape[0])

    df_sar = df_sar.copy()

    tuples = list(
        zip(n_cves_corrs, n_cves_pvalues, worst_cve_corrs, worst_cve_pvalues, avg_cve_corrs, avg_cve_pvalues, supports)
    )
    dct = dict(zip(["eal"] + families, tuples))
    df_corr = pd.DataFrame.from_dict(
        dct,
        orient="index",
        columns=[
            "n_cves_corr",
            "n_cves_pvalue",
            "worst_cve_score_corr",
            "worst_cve_pvalue",
            "avg_cve_score_corr",
            "avg_cve_pvalue",
            "support",
        ],
    )
    df_corr.style.set_caption("Correlations between EAL, SARs and CVEs")
    df_corr = df_corr.sort_values(by="support", ascending=False)

    if filter_nans:
        df_corr = df_corr.dropna(how="any", subset=["n_cves_corr", "worst_cve_score_corr", "avg_cve_score_corr"])

    if output_path:
        df_corr.to_csv(output_path)

    return df_corr


def find_earliest_maintenance_after_cve(row):
    "Given dataframe row, will return first maintenance date succeeding first published CVE related to a certificate if exists, else np.nan"
    maintenances_after_cve = [x for x in row["maintenance_dates"] if x > row["earliest_cve"]]
    return min(maintenances_after_cve) if maintenances_after_cve else np.nan


def filter_to_cves_within_validity_period(cc_df: pd.DataFrame, cve_dset: CVEDataset) -> pd.DataFrame:
    """
    Filters the column `related_cves` in `cc_df` DataFrame to CVEs that were published within validity period of the
    studied certificate.
    """

    def filter_cves(
        cve_dset: CVEDataset, cves: set[str], not_valid_before: pd.Timestamp, not_valid_after: pd.Timestamp
    ) -> set[str] | float:
        # Mypy is complaining, but the Optional date is resolved at the beginning of the and condition
        result: set[str] = {
            x
            for x in cves
            if cve_dset[x].published_date
            and not_valid_before < pd.Timestamp(cve_dset[x].published_date.date())  # type: ignore
            and not_valid_after > pd.Timestamp(cve_dset[x].published_date.date())  # type: ignore
        }

        return result if result else np.nan

    if (
        cc_df.loc[
            (cc_df.related_cves.notnull()) & ((cc_df.not_valid_before.isna()) | (cc_df.not_valid_after.isna()))
        ].shape[0]
        > 0
    ):
        raise ValueError(
            "Cannot filter CVEs on certificates that have NaNs in not_valid_after or not_valid_before fields."
        )

    cc_df["related_cves"] = cc_df.apply(
        lambda row: filter_cves(cve_dset, row["related_cves"], row["not_valid_before"], row["not_valid_after"])
        if not pd.isna(row["related_cves"])
        else row["related_cves"],
        axis=1,
    )

    return cc_df


def expand_df_with_cve_cols(df: pd.DataFrame, cve_dset: CVEDataset) -> pd.DataFrame:
    df = df.copy()
    df["n_cves"] = df.related_cves.map(lambda x: 0 if pd.isna(x) else len(x))
    df["cve_published_dates"] = df.related_cves.map(
        lambda x: [cve_dset[y].published_date.date() for y in x] if not pd.isna(x) else np.nan  # type: ignore
    )

    df["earliest_cve"] = df.cve_published_dates.map(lambda x: min(x) if isinstance(x, list) else np.nan)
    df["worst_cve_score"] = df.related_cves.map(
        lambda x: max([cve_dset[cve].metrics.base_score for cve in x]) if not pd.isna(x) else np.nan
    )

    """
    Note: Technically, CVE can have 0 base score. This happens when the CVE is discarded from the database.
    This could skew the results. During May 2022 analysis, we encountered a single CVE with such score.
    Therefore, we do not treat this case.
    To properly treat this, the average should be taken across CVEs with >0 base_socre.
    """
    df["avg_cve_score"] = df.related_cves.map(
        lambda x: np.mean([cve_dset[cve].metrics.base_score for cve in x]) if not pd.isna(x) else np.nan
    )
    return df


def prepare_cwe_df(
    cc_df: pd.DataFrame, cve_dset: CVEDataset, fine_grained: bool = False
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    This function does the following:
    1. Filter CC DF to columns relevant for CWE examination (eal, related_cves, category)
    2. Parses CWE webpage of CWE categories and weaknesses, fetches CWE descriptions and names from there
    3. Explodes the CC DF so that each row corresponds to single CVE
    4. Joins CC DF with CWE DF obtained from CVEDataset
    5. Explodes resulting DF again so that each row corresponds to single CWE

    :param pd.DataFrame cc_df: DataFrame obtained from CCDataset, should be limited to rows with >0 vulnerabilities
    :param CVEDataset cve_dset: CVEDataset instance to retrieve CWE data from
    :param bool fine_grained: If se to True, CWEs won't be merged into weaknesses of higher abstraction
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
    dct: dict[str, Any] = {
        "cwe_id": [],
        "cwe_name": [],
        "cwe_description": [],
        "type": [],
        "child_of": [],
    }

    assert weaknesses
    for weakness in weaknesses:
        assert weakness
        description = weakness.find("{http://cwe.mitre.org/cwe-6}Description")
        related_weaknesses = weakness.find("{http://cwe.mitre.org/cwe-6}Related_Weaknesses")

        dct["cwe_id"].append("CWE-" + weakness.attrib["ID"])
        dct["cwe_name"].append(weakness.attrib["Name"])
        dct["cwe_description"].append(description.text if description is not None else None)
        dct["type"].append("weakness")

        if related_weaknesses:
            dct["child_of"].append(
                {
                    "CWE-" + x.attrib["CWE_ID"]
                    for x in related_weaknesses
                    if x.tag == "{http://cwe.mitre.org/cwe-6}Related_Weakness" and x.attrib["Nature"] == "ChildOf"
                }
            )
        else:
            dct["child_of"].append(np.nan)

    assert categories
    for category in categories:
        assert category
        summary = category.find("{http://cwe.mitre.org/cwe-6}Summary")

        dct["cwe_id"].append("CWE-" + category.attrib["ID"])
        dct["cwe_name"].append(category.attrib["Name"])
        dct["cwe_description"].append(summary.text if summary is not None else None)
        dct["type"].append("category")
        dct["child_of"].append(np.nan)

    cwe_df = pd.DataFrame(dct).set_index("cwe_id")
    cwe_df["url"] = cwe_df.index.map(lambda x: "https://cwe.mitre.org/data/definitions/" + x.split("-")[1] + ".html")
    cwe_df = cwe_df.replace(r"\n", " ", regex=True)

    if fine_grained:
        return df_cwe_relevant, cwe_df
    else:
        return get_coarse_grained_cwes(df_cwe_relevant, cwe_df), cwe_df


def get_coarse_grained_cwes(fine_grained_df: pd.DataFrame, cwe_df: pd.DataFrame) -> pd.DataFrame:
    """
    Oddly enough, NVD contains CWEs at different levels of abstraction, which makes it difficult to compare between them.
    Among others, some three different CWEs appear in the CVEDataset: CWE-20, CWE-119, CWE-787. Problem is that CWE-787
    is child of CWE-119, which in turn is child of CWE-20. It makes no sense to compute stats of most prevalent CWEs
    unless categories are aligned to the top-most level.

    This function aligns the categories to the top-most level. It works in loop. When an iteration is performed without
    replacing any CWEs with their parents, the algorithm terminates.
    The algorithm inspects every CWE and replaces it with all its parents on condition that they appear in the CVE Dataset.

    :param pd.DataFrame fine_grained_df: First element of the output of `prepare_cwe_df` function
    :param pd.DataFrame cwe_df: Second element of the output of `prepare_cwe_df` function
    :return pd.DataFrame: DF obtained from CC Dataset, fully exploded to coarse-grained CWEs
    """
    all_cwes_in_original_df = set(fine_grained_df.cwe_id.unique())
    parent_dict = cwe_df.child_of.to_dict()
    new_set = set(fine_grained_df.cwe_id.unique())
    mapping = {x: {x} for x in new_set}

    while True:
        old_set = copy.deepcopy(new_set)
        for cwe in old_set:
            parents = parent_dict[cwe]
            if parents and parents is not np.nan and any(x in all_cwes_in_original_df for x in parents):
                new_set.remove(cwe)
                new_set.update({x for x in parents if x in all_cwes_in_original_df})
                for val in mapping.values():
                    if cwe in val:
                        val.remove(cwe)
                        val.update({x for x in parents if x in all_cwes_in_original_df})
        if new_set == old_set:
            break

    # Now we should have complete mapping of fine_grained -> coarse_grained CWEs
    new_df = fine_grained_df.copy()
    new_df.cwe_id = new_df.cwe_id.map(mapping)

    return new_df.explode(column="cwe_id")


def get_top_n_cwes(
    df: pd.DataFrame, cwe_df: pd.DataFrame, category: str | None = None, eal: str | None = None, n_cwes: int = 10
) -> pd.DataFrame:
    """Fetches top-n CWEs, overall, per category, or per EAL"""
    top_n = df.copy()

    if category:
        top_n = top_n.loc[top_n.category == category].copy()
    if eal:
        top_n = top_n.loc[top_n.eal == eal].copy()

    top_n = (
        top_n.cwe_id.value_counts()
        .head(n_cwes)
        .to_frame()
        .rename(columns={"cwe_id": "frequency"})
        .rename_axis("cwe_id")
    )
    top_n["cwe_name"] = top_n.index.map(lambda x: cwe_df.loc[x].cwe_name)
    top_n["cwe_description"] = top_n.index.map(lambda x: cwe_df.loc[x].cwe_description)
    top_n["url"] = top_n.index.map(lambda x: cwe_df.loc[x].url)
    top_n["type"] = top_n.index.map(lambda x: cwe_df.loc[x].type)

    return top_n


def compute_maintenances_that_come_after_vulns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Given pre-processed CCDataset DataFrame (expanded with MU & CVE cols), computes time to fix CVE and earliest CVE after some vuln.
    """
    df_fixed = df.loc[(df.n_cves > 0) & (df.n_maintenances > 0)].copy()
    df_fixed.maintenance_dates = df_fixed.maintenance_dates.map(lambda x: [y.date() for y in x])
    df_fixed.loc[:, "earliest_maintenance_after_vuln"] = df_fixed.apply(find_earliest_maintenance_after_cve, axis=1)
    df_fixed.index.name = "dgst"
    return df_fixed


def move_fixing_mu_to_directory(
    df_fixed: pd.DataFrame, main_df: pd.DataFrame, outdir: str | Path, inpath: str | Path
) -> pd.DataFrame:
    """
    Localizes reports of maintenance updates that should fix some vulnerability and copies them into a directory.
    df_fixed should be the output of compute_maintenances_that_come_after_vulns method.
    """
    fixed_df_index = (
        df_fixed.loc[~df_fixed.earliest_maintenance_after_vuln.isnull()]
        .reset_index()
        .set_index(["dgst", "earliest_maintenance_after_vuln"])
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


def plot_dataframe_graph(
    data: dict,
    label: str,
    file_name: str,
    density: bool = False,
    cumulative: bool = False,
    bins: int = 50,
    log: bool = True,
    show: bool = True,
) -> None:
    pd_data = pd.Series(data)
    pd_data.hist(bins=bins, label=label, density=density, cumulative=cumulative)
    plt.savefig(file_name)
    if show:
        plt.show()

    if log:
        sorted_data = pd_data.value_counts(ascending=True)

    logger.info(sorted_data.where(sorted_data > 1).dropna())
