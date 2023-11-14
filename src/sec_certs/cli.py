#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import click
from pydantic import ValidationError

from sec_certs.configuration import config
from sec_certs.dataset.cc import CCDataset
from sec_certs.dataset.dataset import Dataset
from sec_certs.dataset.fips import FIPSDataset
from sec_certs.utils.helpers import warn_if_missing_poppler, warn_if_missing_tesseract

logger = logging.getLogger(__name__)

EXIT_CODE_NOK: int = 1
EXIT_CODE_OK: int = 0

DEFAULT_OUTPUTPATH: Path = Path("./dataset").resolve()


@dataclass
class ProcessingStep:
    name: str
    processing_function_name: str
    preconditions: list[str] = field(default_factory=list)
    precondition_error_msg: str | None = field(default=None)
    pre_callback_func: Callable | None = field(default=None)

    def __post_init__(self) -> None:
        for condition in self.preconditions:
            if not hasattr(Dataset.DatasetInternalState, condition):
                raise ValueError(f"Precondition attribute {condition} is not member of `Dataset.DatasetInternalState`.")

    def run(self, dset: CCDataset | FIPSDataset) -> None:
        for condition in self.preconditions:
            if not getattr(dset.state, condition):
                err_msg = (
                    self.precondition_error_msg
                    if self.precondition_error_msg
                    else f"Error, precondition to run {self.name} not met, exiting."
                )
                click.echo(err_msg, err=True)
                sys.exit(EXIT_CODE_NOK)
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
    outputpath: Path | None,
) -> CCDataset | FIPSDataset:
    constructor: type[CCDataset] | type[FIPSDataset] = CCDataset if framework == "cc" else FIPSDataset
    dset: CCDataset | FIPSDataset

    if to_build:
        if not outputpath:
            outputpath = DEFAULT_OUTPUTPATH
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
        if not inputpath:
            click.echo(
                "Error: If you do not use 'build' action, you must provide --input parameter to point to an existing dataset.",
                err=True,
            )
            sys.exit(EXIT_CODE_NOK)

        dset = constructor.from_json(inputpath)

        if outputpath and dset.root_dir != outputpath:
            print(
                "Warning: you provided both input and output paths. The dataset from input path will get copied to output path."
            )
            dset.copy_dataset(outputpath)

    return dset


steps = [
    ProcessingStep(
        "process-aux-dsets",
        "process_auxiliary_datasets",
        preconditions=["meta_sources_parsed"],
        precondition_error_msg="Error: You want to process the auxiliary datasets, but the data from cert. framework website was not parsed. You must use 'build' action first.",
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
        preconditions=["artifacts_downloaded"],
        precondition_error_msg="Error: You want to convert pdfs -> txt, but the pdfs were not downloaded. You must use 'download' action first.",
        pre_callback_func=warn_missing_libs,
    ),
    ProcessingStep(
        "analyze",
        "analyze_certificates",
        preconditions=["pdfs_converted", "auxiliary_datasets_processed"],
        precondition_error_msg="Error: You want to process txt documents of certificates, but pdfs were not converted. You must use 'convert' action first.",
        pre_callback_func=None,
    ),
]


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
    "outputpath",
    type=click.Path(file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True),
    help="Path where the output of the experiment will be stored. May overwrite existing content.",
)
@click.option(
    "-c",
    "--config",
    "configpath",
    default=None,
    type=click.Path(file_okay=True, dir_okay=False, writable=True, readable=True),
    help="Path to your own config yaml file that will override the default config.",
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
    outputpath: Path | None,
    configpath: Path | None,
    inputpath: Path | None,
    quiet: bool,
):
    try:
        if configpath:
            try:
                config.load_from_yaml(configpath)
            except FileNotFoundError:
                click.echo("Error: Bad path to configuration file", err=True)
                sys.exit(EXIT_CODE_NOK)
            except (ValueError, ValidationError) as e:
                click.echo(f"Error: Bad format of configuration file: {e}", err=True)
                sys.exit(EXIT_CODE_NOK)

        file_handler = logging.FileHandler(config.log_filepath)
        stream_handler = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)
        handlers: list[logging.StreamHandler] = [file_handler] if quiet else [file_handler, stream_handler]
        logging.basicConfig(level=logging.INFO, handlers=handlers)
        start = datetime.now()

        actions_set = (
            {"build", "process-aux-dsets", "download", "convert", "analyze"} if "all" in actions else set(actions)
        )

        dset = build_or_load_dataset(framework, inputpath, "build" in actions_set, outputpath)
        aux_dsets_to_handle = "PP, Maintenance updates" if framework == "cc" else "Algorithms"
        aux_dsets_to_handle += "CPE, CVE"

        processing_step: ProcessingStep
        for processing_step in [x for x in steps if x.name in actions_set]:
            processing_step.run(dset)

        end = datetime.now()
        logger.info(f"The computation took {(end-start)} seconds.")
    except Exception as e:
        click.echo(
            f"Unhandled exception: {e}",
            err=True,
        )
        return EXIT_CODE_NOK
    return EXIT_CODE_OK


if __name__ == "__main__":
    main()
