#!/usr/bin/env python3

import click

from sec_certs.dataset import IUTDataset


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.argument("output", type=click.Path(dir_okay=False, writable=True))
def main(directory, output):
    """
    Parse FIPS 'Implementation Under Test' pages.

    \b
    To use, download pages from the URL:
    https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/IUT-List
    into a directory `d` and name them `fips_iut_<iso-timestamp>.html`.

    \b
    Then run:
      in_process.py fips-iut d output.json
    to obtain the parsed output in `output.json`.
    """
    dataset = IUTDataset.from_dumps(directory)
    dataset.to_json(output)


if __name__ == "__main__":
    main()
