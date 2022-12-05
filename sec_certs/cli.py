#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

import click

from sec_certs import constants
from sec_certs.config.configuration import config
from sec_certs.dataset import CCDataset, FIPSDataset
from sec_certs.utils.helpers import warn_if_missing_poppler, warn_if_missing_tesseract

logger = logging.getLogger(__name__)


@dataclass
class ProcessingStep:
    name: str
    processing_function_name: str
    preconditions: list[str] = field(default_factory=list)
    precondition_error_msg: str | None = field(default=None)
    pre_callback_func: Callable | None = field(default=None)

    def run(self, dset: CCDataset | FIPSDataset) -> None:
        for condition in self.preconditions:
            if not getattr(dset.state, condition):
                err_msg = (
                    self.precondition_error_msg
                    if self.precondition_error_msg
                    else f"Error, precondition to run {self.name} not met, exiting."
                )
                print(err_msg)
                sys.exit(1)
        if self.pre_callback_func:
            self.pre_callback_func()

        getattr(dset, self.processing_function_name)()


def warn_missing_libs():
    warn_if_missing_poppler()
    warn_if_missing_tesseract()


def build_or_load_dataset(
    framework: str,
    inputpath: Path | None,
    to_build: bool,
    outputpath: Path = constants.DUMMY_NONEXISTING_PATH,
) -> CCDataset | FIPSDataset:
    constructor: type[CCDataset] | type[FIPSDataset] = CCDataset if framework == "cc" else FIPSDataset
    dset: CCDataset | FIPSDataset

    if to_build:
        if inputpath:
            print(
                f"Warning: you wanted to build a dataset but you provided one in JSON -- that will be ignored. New one will be constructed at: {outputpath}"
            )
        dset = constructor(
            certs={},
            root_dir=outputpath,
            name=framework + "_dataset",
            description=f"Full {framework} dataset snapshot {datetime.now().date()}",
        )
        dset.get_certs_from_web()
    else:
        if inputpath:
            dset = constructor.from_json(inputpath)
            if outputpath and dset.root_dir != outputpath:
                print(
                    "Warning: you provided both input and output paths. The dataset from input path will get copied to output path."
                )
                dset.root_dir = outputpath
        else:
            print(
                "Error: If you do not use 'build' action, you must provide --input parameter to point to an existing dataset."
            )
            sys.exit(1)

    return dset


@click.command()
@click.argument(
    "framework",
    required=True,
    nargs=1,
    type=click.Choice(["cc", "fips"], case_sensitive=False),
)
@click.argument(
    "actions",
    required=True,
    nargs=-1,
    type=click.Choice(["all", "build", "process-aux-dsets", "download", "convert", "analyze"], case_sensitive=False),
)
@click.option(
    "-o",
    "--output",
    type=click.Path(file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True),
    help="Path where the output of the experiment will be stored. May overwrite existing content.",
    default=Path("./dataset/"),
    show_default=True,
)
@click.option(
    "-c",
    "--config",
    "configpath",
    default=None,
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=True),
    help="Path to your own config yaml file that will override the default one.",
)
@click.option(
    "-i",
    "--input",
    "inputpath",
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=True),
    help="If set, the actions will be performed on a CC dataset loaded from JSON from the input path.",
)
@click.option("-q", "--quiet", is_flag=True, help="If set, will not print to stdout")
def main(
    framework: str,
    actions: list[str],
    outputpath: Path,
    configpath: str | None,
    inputpath: Path | None,
    silent: bool,
):
    try:
        file_handler = logging.FileHandler(config.log_filepath)
        stream_handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)
        handlers: list[logging.StreamHandler] = [file_handler] if silent else [file_handler, stream_handler]
        logging.basicConfig(level=logging.INFO, handlers=handlers)
        start = datetime.now()

        if configpath:
            try:
                config.load(Path(configpath))
            except FileNotFoundError:
                print("Error: Bad path to configuration file")
                sys.exit(1)
            except ValueError as e:
                print(f"Error: Bad format of configuration file: {e}")

        actions_set = (
            {"build", "process-aux-dsets", "download", "convert", "analyze", "maintenances"}
            if "all" in actions
            else set(actions)
        )

        dset = build_or_load_dataset(framework, inputpath, "build" in actions_set, outputpath)
        aux_dsets_to_handle = "PP, Maintenance updates" if framework == "cc" else "Algorithms"
        analysis_pre_callback = None

        steps = [
            ProcessingStep(
                "process-aux-dsets",
                "process_auxillary_datasets",
                preconditions=["meta_sources_parsed"],
                precondition_error_msg=f"Error: You want to process the auxillary datasets: {aux_dsets_to_handle} , but the data from cert. framework website was not parsed. You must use 'build' action first.",
                pre_callback_func=None,
            ),
            ProcessingStep(
                "download",
                "download_all_artifacts",
                preconditions=["meta_sources_parsed"],
                precondition_error_msg="Error: You want to download all artifacts, but the data from the cert. framework website was not parsed. You must use 'build' action first.",
                pre_callback_func=None,
            ),
            ProcessingStep(
                "convert",
                "convert_all_pdfs",
                preconditions=["pdfs_downloaded"],
                precondition_error_msg="Error: You want to convert pdfs -> txt, but the pdfs were not downloaded. You must use 'download' action first.",
                pre_callback_func=warn_missing_libs,
            ),
            ProcessingStep(
                "analyze",
                "analyze_certificates",
                preconditions=["pdfs_converted", "auxillary_datasets_processed"],
                precondition_error_msg="Error: You want to process txt documents of certificates, but pdfs were not converted. You must use 'convert' action first.",
                pre_callback_func=analysis_pre_callback,
            ),
        ]

        processing_step: ProcessingStep
        for processing_step in [x for x in steps if x in actions_set]:
            processing_step.run(dset)

        end = datetime.now()
        logger.info(f"The computation took {(end-start)} seconds.")
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    main()
