from pathlib import Path
from shutil import copyfile
from typing import List, Optional, Set, Union

import numpy as np
import pandas as pd
from tqdm.notebook import tqdm

from sec_certs.dataset.cve import CVEDataset
from sec_certs.sample.sar import SAR


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
