from __future__ import annotations

import json
import logging
from pathlib import Path

from tqdm import tqdm

from sec_certs.configuration import config
from sec_certs.dataset.auxiliary_dataset_handling import CPEDatasetHandler
from sec_certs.dataset.dataset import Dataset
from sec_certs.sample.cpe import CPE

logger = logging.getLogger(__name__)


def to_label_studio_json(dataset: Dataset, output_path: str | Path) -> None:
    dataset.load_auxiliary_datasets()
    cpe_dset = dataset.aux_handlers[CPEDatasetHandler].dset

    lst = []
    for cert in [x for x in dataset if x.heuristics.cpe_matches]:
        dct = {"text": cert.label_studio_title}
        candidates = [cpe_dset[x].title for x in cert.heuristics.cpe_matches]
        candidates += ["No good match"] * (config.cpe_n_max_matches - len(candidates))
        options = ["option_" + str(x) for x in range(1, config.cpe_n_max_matches)]
        dct.update(dict(zip(options, candidates)))
        lst.append(dct)

    with Path(output_path).open("w") as handle:
        json.dump(lst, handle, indent=4)


def load_label_studio_labels(dataset: Dataset, input_path: str | Path) -> set[str]:
    with Path(input_path).open("r") as handle:
        data = json.load(handle)

    dataset.load_auxiliary_datasets()
    cpe_dset = dataset.aux_handlers[CPEDatasetHandler].dset
    title_to_cpes_dict = cpe_dset.get_title_to_cpes_dict()
    labeled_cert_digests: set[str] = set()

    logger.info("Translating label studio matches into their CPE representations and assigning to certificates.")
    for annotation in tqdm(data, desc="Translating label studio matches"):
        cpe_candidate_keys = {key for key in annotation if "option_" in key and annotation[key] != "No good match"}

        if "verified_cpe_match" not in annotation:
            incorrect_keys: set[str] = set()
        elif isinstance(annotation["verified_cpe_match"], str):
            incorrect_keys = {annotation["verified_cpe_match"]}
        else:
            incorrect_keys = set(annotation["verified_cpe_match"]["choices"])

        incorrect_keys = {x.lstrip("$") for x in incorrect_keys}
        predicted_annotations = {annotation[x] for x in cpe_candidate_keys - incorrect_keys}

        cpes: set[CPE] = set()
        for x in predicted_annotations:
            if x not in title_to_cpes_dict:
                logger.error(f"{x} not in dataset")
            else:
                to_update = title_to_cpes_dict[x]
                if to_update and not cpes:
                    cpes = to_update
                elif to_update and cpes:
                    cpes.update(to_update)

        # distinguish between FIPS and CC
        if "\n" in annotation["text"]:
            cert_name = annotation["text"].split("\nModule name: ")[1].split("\n")[0]
        else:
            cert_name = annotation["text"]

        certs = dataset.get_certs_by_name(cert_name)
        labeled_cert_digests.update({x.dgst for x in certs})

        for c in certs:
            c.heuristics.verified_cpe_matches = {x.uri for x in cpes if x is not None} if cpes else None

    return labeled_cert_digests
