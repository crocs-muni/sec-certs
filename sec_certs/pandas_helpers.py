from pathlib import Path
from typing import List, Optional, Set, Union

import pandas as pd
from tqdm.notebook import tqdm

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
    Computes correlations of EAL and different SARs and two columns: (n_cves, worst_cve). Few assumptions about the passed dataframe:
    - EAL column must be categorical data type
    - SAR column must be a set of SARs
    - `n_cves` and `worst_cve` columns must be present in the dataframe
    Possibly, it can filter columns will both values NaN (due to division by zero or super low supports.)
    """
    df_sar = df.loc[:, ["highest_security_level", "sars", "worst_cve", "n_cves"]]
    df_sar = df_sar.rename(columns={"highest_security_level": "EAL"})
    families = discover_sar_families(df_sar.sars)
    df_sar.EAL = df_sar.EAL.cat.codes

    if exclude_vuln_free_certs:
        df_sar = df_sar.loc[df_sar.n_cves > 0]

    n_cves_corrs = [df_sar["EAL"].corr(df_sar.n_cves)]
    worst_cve_corrs = [df_sar["EAL"].corr(df_sar.worst_cve)]
    supports = [df_sar.loc[~df_sar["EAL"].isnull()].shape[0]]

    for family in tqdm(families):
        df_sar[family] = df_sar.sars.map(lambda x: get_sar_level_from_set(x, family))
        n_cves_corrs.append(df_sar[family].corr(df_sar.n_cves))
        worst_cve_corrs.append(df_sar[family].corr(df_sar.worst_cve))
        supports.append(df_sar.loc[~df_sar[family].isnull()].shape[0])
    df_sar = df_sar.copy()

    tuples = list(zip(n_cves_corrs, worst_cve_corrs, supports))
    dct = {family: correlations for family, correlations in zip(["EAL"] + families, tuples)}
    df_corr = pd.DataFrame.from_dict(dct, orient="index", columns=["n_cves_corr", "worst_cve_corr", "support"])
    df_corr.style.set_caption("Correlations between EAL, SARs and CVEs")

    if filter_nans:
        df_corr = df_corr.dropna(how="all", subset=["n_cves_corr", "worst_cve_corr"])

    if output_path:
        df_corr.to_csv(output_path)

    return df_corr
