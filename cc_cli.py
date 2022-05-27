#!/usr/bin/env python3
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click

from sec_certs.config.configuration import config
from sec_certs.dataset import CCDataset
from sec_certs.helpers import warn_if_missing_poppler

logger = logging.getLogger(__name__)


@click.command()
@click.argument(
    "actions",
    required=True,
    nargs=-1,
    type=click.Choice(["all", "build", "download", "convert", "analyze", "maintenances"], case_sensitive=False),
)
@click.option(
    "-o",
    "--output",
    type=click.Path(file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True),
    help="Path where the output of the experiment will be stored. May overwrite existing content.",
    default=Path("./cc_dset/"),
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
@click.option("-s", "--silent", is_flag=True, help="If set, will not print to stdout")
def main(
    configpath: Optional[str], actions: List[str], inputpath: Optional[Path], output: Optional[Path], silent: bool
):
    """
    Specify actions, sequence of one or more strings from the following list: [all, build, download, convert, analyze]
    If 'all' is specified, all actions run against the dataset. Otherwise, only selected actions will run in the correct order.
    """
    file_handler = logging.FileHandler(config.log_filepath)
    stream_handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    handlers: List[logging.StreamHandler] = [file_handler]

    if output:
        output = Path(output)

    if not inputpath and not output:
        print(
            "Error: You did not specify path to load the dataset from, nor did you specify where dataset can be stored."
        )
        sys.exit(1)

    if not silent:
        handlers.append(stream_handler)

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

    actions_set = {"build", "download", "convert", "analyze", "maintenances"} if "all" in actions else set(actions)

    if inputpath and "build" not in actions_set:
        dset: CCDataset = CCDataset.from_json(Path(inputpath))
        if output:
            print(
                "Warning: you provided both input and output paths. The dataset from input path will get copied to output path."
            )
            dset.root_dir = output

    if inputpath and "build" in actions_set:
        print(
            f"Warning: you wanted to build a dataset but you provided one in JSON -- that will be ignored. New one will be constructed at: {output}"
        )

    if "build" in actions_set:
        if output is None:
            raise RuntimeError("Output path was not provided.")
        dset = CCDataset(
            certs={},
            root_dir=output,
            name="CommonCriteria_dataset",
            description=f"Full CommonCriteria dataset snapshot {datetime.now().date()}",
        )
        dset.get_certs_from_web()
        dset.process_protection_profiles()
    elif "build" not in actions_set and not inputpath:
        print("Error: If you do not provide input parameter, you must use 'build' action to build dataset first.")
        sys.exit(1)

    if "download" in actions_set:
        if not dset.state.meta_sources_parsed:
            print(
                "Error: You want to download all pdfs, but the data from commoncriteria.org was not parsed. You must use 'build' action first."
            )
            sys.exit(1)
        dset.download_all_pdfs()

    if "convert" in actions_set:
        if not dset.state.pdfs_downloaded:
            print(
                "Error: You want to convert pdfs -> txt, but the pdfs were not downloaded. You must use 'download' action first."
            )
            sys.exit(1)
        warn_if_missing_poppler()
        dset.convert_all_pdfs()

    if "analyze" in actions_set:
        if not dset.state.pdfs_converted:
            print(
                "Error: You want to process txt documents of certificates, but pdfs were not converted. You must use 'convert' action first."
            )
            sys.exit(1)
        dset.analyze_certificates()

    if "maintenances" in actions_set:
        if not dset.state.meta_sources_parsed:
            print(
                "Error: You want to process maintenance updates, but the data from commoncriteria.org was not parsed. You must use 'build' action first."
            )
            sys.exit(1)
        dset.process_maintenance_updates()

    end = datetime.now()
    logger.info(f"The computation took {(end-start)} seconds.")


if __name__ == "__main__":
    main()
