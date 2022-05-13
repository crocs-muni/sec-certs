#!/usr/bin/env python3

import click

from sec_certs.dataset import MIPDataset


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.argument("output", type=click.Path(dir_okay=False, writable=True))
def main(directory, output):
    """
    Parse FIPS 'Modules In Process' pages.

    \b
    To use, download pages from the URL:
    https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List
    into a directory `d` and name them `fips_mip_<iso-timestamp>.html`.

    \b
    Then run:
      in_process.py fips-mip d output.json
    to obtain the parsed output in `output.json`.
    """
    dataset = MIPDataset.from_dumps(directory)
    dataset.to_json(output)


if __name__ == "__main__":
    main()
