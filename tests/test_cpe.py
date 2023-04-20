from __future__ import annotations

from pathlib import Path

import pytest

from sec_certs import constants
from sec_certs.dataset import CPEDataset
from sec_certs.sample import CPE
from sec_certs.serialization.json import SerializationError


def test_cpe_dset_from_json(cpe_dataset_path: Path, cpe_dataset: CPEDataset, tmp_path: Path):
    assert CPEDataset.from_json(cpe_dataset_path) == cpe_dataset

    compressed_path = tmp_path / "dset.json.gz"
    cpe_dataset.to_json(compressed_path, compress=True)
    decompressed_dataset = CPEDataset.from_json(compressed_path, is_compressed=True)
    assert cpe_dataset == decompressed_dataset


def test_cpe_parsing():
    potentially_problematic_cpes = {
        'cpe:2.3:a:bayashi:dopvstar\\::0091:*:*:*:*:*:*:*"': ("bayashi", "dopvstar:", "0091"),
        "cpe:2.3:a:moundlabs:\\:\\:mound\\:\\::2.1.6:*:*:*:*:*:*:*": ("moundlabs", "::mound::", "2.1.6"),
        "cpe:2.3:a:lemonldap-ng:lemonldap\\:\\::*:*:*:*:*:*:*:*": (
            "lemonldap-ng",
            "lemonldap::",
            constants.CPE_VERSION_NA,
        ),
        "cpe:2.3:o:cisco:nx-os:5.0\\\\\\(3\\\\\\)u5\\\\\\(1g\\\\\\):*:*:*:*:*:*:*": (
            "cisco",
            "nx-os",
            "5.0\\(3\\)u5\\(1g\\)",
        ),
        "cpe:2.3:a:\\@thi.ng\\/egf_project:\\@thi.ng\\/egf:-:*:*:*:*:node.js:*:*": (
            "@thi.ng/egf project",
            "@thi.ng/egf",
            "-",
        ),
        "cpe:2.3:a:oracle:communications_diameter_signaling_router_idih\\:::*:*:*:*:*:*:*": (
            "oracle",
            "communications diameter signaling router idih:",
            constants.CPE_VERSION_NA,
        ),
    }
    for uri, tpl in potentially_problematic_cpes.items():
        cpe = CPE("", uri)
        assert cpe.vendor == tpl[0]
        assert cpe.item_name == tpl[1]
        assert cpe.version == tpl[2]


def test_cpe_from_to_dict(cpe_dataset: CPEDataset):
    cpe = cpe_dataset["cpe:2.3:a:ibm:security_key_lifecycle_manager:2.6.0.1:*:*:*:*:*:*:*"]
    dct = cpe.to_dict()
    other_cpe = CPE.from_dict(dct)
    assert cpe == other_cpe


def test_to_pandas(cpe_dataset: CPEDataset):
    df = cpe_dataset.to_pandas()
    assert df.shape == (len(cpe_dataset), len(CPE.pandas_columns) - 1)
    assert df.index.name == "uri"
    assert set(df.columns) == set(CPE.pandas_columns) - {"uri"}


def test_serialization_missing_path():
    dummy_dset = CPEDataset()
    with pytest.raises(SerializationError):
        dummy_dset.to_json()


def test_enhance_with_nvd_data():
    pass
