#!/usr/bin/env python3
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

import click

from sec_certs.config.configuration import DEFAULT_CONFIG_PATH, config
from sec_certs.dataset import FIPSDataset
from sec_certs.helpers import warn_if_missing_graphviz, warn_if_missing_poppler

logger = logging.getLogger(__name__)


@click.command()
@click.argument(
    "actions",
    required=True,
    nargs=-1,
    type=click.Choice(
        ["new-run", "all", "build", "convert", "update", "pdf-scan", "table-search", "analysis", "graphs"],
        case_sensitive=False,
    ),
)
@click.option(
    "-o",
    "--output",
    type=click.Path(file_okay=False, dir_okay=True, writable=True, readable=True, resolve_path=True),
    help="Path to the directory where the output of the 'build' or 'new-run' actions will be stored.",
    default=Path("./fips_dset/"),
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
    help="If set, the actions will be performed on a FIPS dataset loaded from JSON from the input path.",
)
@click.option(
    "-n",
    "--name",
    "json_name",
    default=str(datetime.now().strftime("%d-%n-%Y-%H:%M:%S")) + ".json",
    type=str,
    help="Name of the json object to be created in the <<output>> directory. Defaults to <<timestamp>>.json.",
)
@click.option("--no-download-algs", "no_download_algs", help="Don't fetch new algorithm implementations", is_flag=True)
@click.option("--redo-web-scan", "redo_web_scan", help="Redo HTML webpage scan from scratch", is_flag=True)
@click.option("--redo-keyword-scan", "redo_keyword_scan", help="Redo PDF keyword scan from scratch", is_flag=True)
@click.option(
    "--higher-precision-results",
    "higher_precision_results",
    help="Redo table search for certificates with high error rate. Behaviour undefined if used on a newly instantiated dataset.",
    is_flag=True,
)
@click.option("-s", "--silent", is_flag=True, help="If set, will not print to stdout")
def main(
    configpath: Optional[str],
    actions: Set[str],
    inputpath: Optional[Path],
    output: Optional[Path],
    silent: bool,
    no_download_algs: bool,
    redo_web_scan: bool,
    redo_keyword_scan: bool,
    higher_precision_results: bool,
    json_name: str,
):
    """
    Specify actions, sequence of one or more strings from the following list:

    ["new-run", "all", "build", "convert", "update", "pdf-scan", "table-search", "analysis", "graphs"]

    If 'new-run' is specified, a new dataset will be created and all the actions will be run.
    If 'all' is specified, dataset will be updated and all actions run against the dataset.
    Otherwise, only selected actions will run in the correct order.

    Dataset loading:

        'build'         Create a skeleton of a new dataset from NIST pages.

        'update'        Load a previously used dataset (created by 'build') and update it with nonprocessed entries from NIST pages.

        Both options download the files needed for analysis.

    Analysis preparation:

        'convert'       Convert all downloaded PDFs.

        'pdf-scan'      Perform a scan of downloaded CMVP security policy documents - Keyword extraction.

        'table-search'  Analyze algorithm implementation entries in tables in security policy documents.

        Analysis preparation actions are by default done only for certificates, where each corresponding action failed.
        This behaviour can be changed using '--redo-*' options.
        These actions are also independent of each other.

    Analysis:

        'analysis'      Merge results from analysis preparation and find dependencies between certificates.

        'graphs'        Plot dependency graphs.
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
        logger.error(
            "You did not specify path to load the dataset from, nor did you specify where dataset can be stored."
        )
        sys.exit(1)

    if not silent:
        handlers.append(stream_handler)

    logging.basicConfig(level=logging.INFO, handlers=handlers)
    start = datetime.now()

    # load config
    if configpath:
        try:
            config.load(Path(configpath))
        except FileNotFoundError:
            logger.error("Bad path to configuration file")
            sys.exit(1)
        except ValueError as e:
            logger.error(f"Bad format of configuration file: {e}")
    else:
        logger.info(f"Using default configuration file at {DEFAULT_CONFIG_PATH}.")

    if "all" in actions and "new-run" in actions:
        logger.error("Only one of 'new-run' and 'all' can be specified.")
        sys.exit(1)

    r_actions = (
        {"convert", "pdf-scan", "table-search", "analysis", "graphs"}
        if "all" in actions or "new-run" in actions
        else set(actions)
    )

    r_actions |= {"build"} if "new-run" in actions else {"update"} if "all" in actions else set()

    actions = r_actions

    if "build" in actions and "update" in actions:
        logger.error(
            "'build' and 'update' cannot be specified at once. Use 'build' to create dataset from scratch, 'update' to update existing dataset."
        )

    if "build" in actions:
        assert output
        if inputpath:
            logger.warning(
                "Both 'build' and 'inputpath' specified. 'build' creates new dataset, 'inputpath' will be ignored."
            )
        dset: FIPSDataset = FIPSDataset(
            certs={},
            root_dir=output,
            name=json_name,
            description=f"Full FIPS dataset snapshot {datetime.now().date()}",
        )
        dset.get_certs_from_web(no_download_algorithms=no_download_algs)
        inputpath = dset.json_path
        output = None

    # only 'build' can work without inputpath
    else:
        if not inputpath:
            logger.error("You must provide inputpath to previously generated dataset with 'build'")
            sys.exit(1)

    assert inputpath
    dset = FIPSDataset.from_json(inputpath)

    assert dset.algorithms

    logger.info(f"Have dataset with {len(dset)} certs and {len(dset.algorithms)} algorithms.")
    if output:
        logger.warning(
            "You provided both inputpath and outputpath, dataset will be copied to outputpath (without data)"
        )
        dset.root_dir = output
        dset.to_json(output)

    if "update" in actions:
        dset.get_certs_from_web(no_download_algorithms=no_download_algs, update=True, redo_web_scan=redo_web_scan)

    if "convert" in actions or "update" in actions:
        warn_if_missing_poppler()
        dset.convert_all_pdfs()

    if "pdf-scan" in actions or "update" in actions:
        dset.pdf_scan(redo=redo_keyword_scan)

    if "table-search" in actions or "update" in actions:
        if not higher_precision_results:
            logger.info(
                "You are using table search without higher precision results. It is advised to use the switch in the next run."
            )
        dset.extract_certs_from_tables(high_precision=higher_precision_results)

    if "analysis" in actions:
        dset.finalize_results()

    if "graphs" in actions:
        warn_if_missing_graphviz()
        dset.plot_graphs(show=True)

    end = datetime.now()
    logger.info(f"The computation took {(end-start)} seconds.")


if __name__ == "__main__":
    main()
