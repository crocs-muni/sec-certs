from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Configuration(BaseSettings):
    """
    Class that holds configuration.
    While not a singleton, the `config` instance from this module is meant to be primarily used.
    """

    model_config = SettingsConfigDict(env_prefix="seccerts_")

    log_filepath: Path = Field(
        "./cert_processing_log.log",
        description="Path to the file, relative to working directory, where the log will be stored.",
    )
    always_false_positive_fips_cert_id_threshold: int = Field(
        40,
        description="During validation we don't connect certificates with number lower than _this_ to connections due to these numbers being typically false positives.",
        ge=0,
    )
    year_difference_between_validations: int = Field(
        7,
        description=" During validation we don't connect certificates with validation dates difference higher than _this_.",
    )
    n_threads: int = Field(
        -1,
        description="How many threads to use for parallel computations. Set to -1 to use all logical cores.",
        ge=-1,
    )
    cpe_matching_threshold: int = Field(
        92,
        description="Level of required string similarity between CPE and certificate name on CC CPE matching, 0-100. Lower values yield more false negatives, higher values more false positives",
        ge=0,
        le=100,
    )
    cpe_n_max_matches: int = Field(
        99,
        description="Maximum number of candidate CPE items that may be related to given certificate, >0",
        gt=0,
    )
    cc_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/cc/dataset.json",
        description="URL from where to fetch the latest snapshot of fully processed CC dataset.",
    )
    cc_latest_full_archive: AnyHttpUrl = Field(
        "https://sec-certs.org/cc/cc.tar.gz",
        description="URL from where to fetch the latest full archive of fully processed CC dataset.",
    )
    cc_maintenances_latest_full_archive: AnyHttpUrl = Field(
        "https://sec-certs.org/cc/cc_mu.tar.gz",
        description="URL from where to fetch the latest full archive of fully processed CC Maintenace updates dataset",
    )
    cc_maintenances_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/cc/maintenance_updates.json",
        description="URL from where to fetch the latest snapshot of CC maintenance updates",
    )
    pp_latest_full_archive: AnyHttpUrl = Field(
        "https://sec-certs.org/pp/pp.tar.gz",
        description="URL from where to fetch the latest full archive of fully processed PP dataset.",
    )
    pp_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/pp/dataset.json",
        description="URL from where to fetch the latest snapshot of the PP dataset.",
    )
    fips_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/fips/dataset.json",
        description="URL for the latest snapshot of FIPS dataset.",
    )
    fips_latest_full_archive: AnyHttpUrl = Field(
        "https://sec-certs.org/fips/fips.tar.gz",
        description="URL from where to fetch the latest full archive of fully processed FIPS dataset.",
    )
    fips_iut_dataset: AnyHttpUrl = Field(
        "https://sec-certs.org/fips/iut/dataset.json",
        description="URL for the dataset of FIPS IUT data.",
    )
    fips_iut_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/fips/iut/latest.json",
        description="URL for the latest snapshot of FIPS IUT data.",
    )
    fips_mip_dataset: AnyHttpUrl = Field(
        "https://sec-certs.org/fips/mip/dataset.json",
        description="URL for the dataset of FIPS MIP data",
    )
    fips_mip_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/fips/mip/latest.json",
        description="URL for the latest snapshot of FIPS MIP data",
    )
    cpe_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/vuln/cpe/cpe.json.gz",
        description="URL for the latest snapshot of CPEDataset.",
    )
    cve_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/vuln/cve/cve.json.gz",
        description="URL for the latest snapshot of CVEDataset.",
    )
    cpe_match_latest_snapshot: AnyHttpUrl = Field(
        "https://sec-certs.org/vuln/cpe/cpe_match.json.gz",
        description="URL for the latest snapshot of cpe match json.",
    )
    fips_matching_threshold: int = Field(
        90,
        description="Level of required similarity before FIPS IUT/MIP entry is considered to match a FIPS certificate.",
        ge=0,
        le=100,
    )
    minimal_token_length: int = Field(
        3,
        description="Minimal length of a string that will be considered as a token during keyword extraction in CVE matching",
        ge=0,
    )
    ignore_first_page: bool = Field(
        True,
        description="During keyword search, first page usually contains addresses - ignore it.",
    )
    cc_reference_annotator_dir: Path | None = Field(  # noqa: UP007
        None,
        description="Path to directory with serialized reference annotator model. If set to `null`, tool will search default directory for the given dataset.",
    )
    cc_reference_annotator_should_train: bool = Field(
        True,
        description="True if new reference annotator model shall be build, False otherwise.",
    )
    cc_matching_threshold: int = Field(
        70,
        description="Level of required similarity before CC scheme entry is considered to match a CC certificate.",
        ge=0,
        le=100,
    )
    cc_use_proxy: bool = Field(False, description="Download CC artifacts through the sec-certs.org proxy.")
    fips_use_proxy: bool = Field(False, description="Download FIPS artifacts through the sec-certs.org proxy.")
    enable_progress_bars: bool = Field(
        True,
        description="If true, progress bars will be printed to stdout during computation.",
    )
    nvd_api_key: str | None = Field(None, description="NVD API key for access to CVEs and CPEs.")  # noqa: UP007
    preferred_source_remote_datasets: Literal["sec-certs", "origin"] = Field(
        "sec-certs",
        description="If set to `sec-certs`, will fetch remote datasets from sec-certs.org."
        + " If set to `origin`, will fetch these resources from their origin URL. It is advised to set an"
        + " `nvd_api_key` when setting this to `origin`.",
    )
    pdf_converter: Literal["pdftotext", "docling"] = Field(
        "pdftotext", description="PDF converter used for all PDF conversions"
    )
    pdf_conversion_workers: int = Field(
        2, description="Number of workers for parallel PDF processing. PDFs are divided into across workers."
    )

    # Recommended when using Docling.
    # Docling instances crashes with weird memory issues during long-running processing. Restarting workers periodically helps prevent it.
    # Recommended value is 80 * pdf_conversion_workers.
    pdf_conversion_max_chunk_size: int | None = Field(
        None,
        description="Maximum number of PDFs to process before restarting the worker pool. Helps control memory usage in converters that gradually accumulate memory during long runs.",
    )

    def _get_nondefault_keys(self) -> set[str]:
        """
        Returns keys of the config that have non-default value, i.e. were provided as kwargs, env. vars. or additionaly set.
        """
        return {key for key, value in Configuration.model_fields.items() if getattr(self, key) != value.default}

    def _set_attrs_from_cfg(self, other_cfg: Configuration, fields_to_set: set[str] | None) -> None:
        if not fields_to_set:
            fields_to_set = set(Configuration.model_fields.keys())
        for field in [x for x in other_cfg.model_fields if x in fields_to_set]:
            setattr(self, field, getattr(other_cfg, field))

    def load_from_yaml(self, yaml_path: str | Path) -> None:
        """
        Will read configuration keys from `yaml_path` and overwrite the corresponding keys in `self`.
        Also, will check environment variables with `seccerts_` prefix.

        :param str | Path yaml_path: path to yaml to read for configuration.
        """
        with Path(yaml_path).open("r") as handle:
            data = yaml.safe_load(handle)
        other_cfg = Configuration.model_validate(data)
        keys_to_rewrite = set(data.keys()).union(other_cfg._get_nondefault_keys())
        self._set_attrs_from_cfg(other_cfg, keys_to_rewrite)

    def to_yaml(self, yaml_path: str | Path) -> None:
        """
        Will dump the configuration to yaml file.

        :param str | Path yaml_path: path where the configuration will be dumped.
        """
        model_dict = json.loads(self.json())  # to assure that we have serializable values
        with Path(yaml_path).open("w") as handle:
            yaml.safe_dump(model_dict, handle)


config = Configuration()
