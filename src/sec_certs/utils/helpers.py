from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Collection
from contextlib import nullcontext
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any

import numpy as np
import pkgconfig
import requests

from sec_certs import constants
from sec_certs.utils import parallel_processing
from sec_certs.utils.tqdm import tqdm

logger = logging.getLogger(__name__)


def download_file(
    url: str, output: Path, delay: float = 0, show_progress_bar: bool = False, progress_bar_desc: str | None = None
) -> str | int:
    try:
        time.sleep(delay)
        # See https://github.com/psf/requests/issues/3953 for header justification
        r = requests.get(
            url,
            allow_redirects=True,
            timeout=constants.REQUEST_TIMEOUT,
            stream=True,
            headers={"Accept-Encoding": None},  # type: ignore
        )
        ctx: Any
        if show_progress_bar:
            ctx = partial(
                tqdm,
                total=int(r.headers.get("content-length", 0)),
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc=progress_bar_desc,
            )
        else:
            ctx = nullcontext

        if r.status_code == requests.codes.ok:
            with ctx() as pbar, output.open("wb") as f:
                for data in r.iter_content(1024):
                    f.write(data)
                    if show_progress_bar:
                        pbar.update(len(data))

            return r.status_code
    except requests.exceptions.Timeout:
        return requests.codes.timeout
    except Exception as e:
        logger.error(f"Failed to download from {url}; {e}")
        return constants.RETURNCODE_NOK
    return constants.RETURNCODE_NOK


def download_parallel(
    urls: Collection[str], paths: Collection[Path], progress_bar_desc: str | None = None
) -> list[int]:
    exit_codes = parallel_processing.process_parallel(
        download_file, list(zip(urls, paths)), unpack=True, progress_bar_desc=progress_bar_desc
    )
    n_successful = len([e for e in exit_codes if e == requests.codes.ok])
    logger.info(f"Successfully downloaded {n_successful} files, {len(exit_codes) - n_successful} failed.")

    for url, e in zip(urls, exit_codes):
        if e != requests.codes.ok:
            logger.error(f"Failed to download {url}, exit code: {e}")

    return exit_codes


def fips_dgst(cert_id: int | str) -> str:
    return get_first_16_bytes_sha256(str(cert_id))


def get_first_16_bytes_sha256(string: str) -> str:
    return hashlib.sha256(string.encode("utf-8")).hexdigest()[:16]


def get_sha256_filepath(filepath: str | Path) -> str:
    hash_sha256 = hashlib.sha256()
    with Path(filepath).open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def to_utc(timestamp: datetime) -> datetime:
    offset = timestamp.utcoffset()
    if offset is None:
        return timestamp
    timestamp -= offset
    return timestamp.replace(tzinfo=None)


def is_in_dict(target_dict: dict, path: str) -> bool:
    current_level = target_dict
    for item in path:
        if item not in current_level:
            return False
        current_level = current_level[item]
    return True


def compute_heuristics_version(cert_name: str) -> set[str]:
    """
    Will extract possible versions from the name of sample
    """
    at_least_something = r"(\b(\d)+\b)"
    just_numbers = r"(\d{1,5})(\.\d{1,5})"

    without_version = r"(" + just_numbers + r"+)"
    long_version = r"(" + r"(\bversion)\s*" + just_numbers + r"+)"
    short_version = r"(" + r"\bv\s*" + just_numbers + r"+)"
    full_regex_string = r"|".join([without_version, short_version, long_version])
    normalizer = r"(\d+\.*)+"

    matched_strings = [max(x, key=len) for x in re.findall(full_regex_string, cert_name, re.IGNORECASE)]
    if not matched_strings:
        matched_strings = [max(x, key=len) for x in re.findall(at_least_something, cert_name, re.IGNORECASE)]
    # Only keep the first occurrence but keep order.
    matches = []
    for match in matched_strings:
        if match not in matches:
            matches.append(match)
    # identified_versions = list(set([max(x, key=len) for x in re.findall(VERSION_PATTERN, cert_name, re.IGNORECASE | re.VERBOSE)]))
    # return identified_versions if identified_versions else ['-']

    if not matches:
        return {constants.CPE_VERSION_NA}

    matched = [re.search(normalizer, x) for x in matches]
    return {x.group() for x in matched if x is not None}


def tokenize_dataset(dset: list[str], keywords: set[str]) -> np.ndarray:
    return np.array([tokenize(x, keywords) for x in dset])


def tokenize(string: str, keywords: set[str]) -> str:
    return " ".join([x for x in string.split() if x.lower() in keywords])


def normalize_fips_vendor(string: str) -> str:
    """
    "Normalizes" FIPS vendor. Precisely:
    - Removes some punctuation and non-alphanumerical symbols
    - Returns only first 5 tokens
    # TODO: The rationale of the steps outlined above should be investigatated
    """
    return " ".join(
        string.replace("(R)", "").replace(",", "").replace("®", "").replace("-", " ").replace("+", " ").split()[:4]
    )


# Credit: https://stackoverflow.com/questions/18092354/
def split_unescape(s: str, delim: str, escape: str = "\\", unescape: bool = True) -> list[str]:
    """
    >>> split_unescape('foo,bar', ',')
    ['foo', 'bar']
    >>> split_unescape('foo$,bar', ',', '$')
    ['foo,bar']
    >>> split_unescape('foo$$,bar', ',', '$', unescape=True)
    ['foo$', 'bar']
    >>> split_unescape('foo$$,bar', ',', '$', unescape=False)
    ['foo$$', 'bar']
    >>> split_unescape('foo$', ',', '$', unescape=True)
    ['foo$']
    """
    ret = []
    current = []
    itr = iter(s)
    for ch in itr:
        if ch == escape:
            try:
                # skip the next character; it has been escaped!
                if not unescape:
                    current.append(escape)
                current.append(next(itr))
            except StopIteration:
                if unescape:
                    current.append(escape)
        elif ch == delim:
            # split! (add current to the list and reset it)
            ret.append("".join(current))
            current = []
        else:
            current.append(ch)
    ret.append("".join(current))
    return ret


def warn_if_missing_poppler() -> None:
    """
    Warns user if he misses a poppler dependency
    """
    try:
        if not pkgconfig.installed("poppler-cpp", ">=0.30"):
            logger.warning(
                "Attempting to run pipeline with pdf->txt conversion, but poppler-cpp dependency was not found."
            )
    except OSError:
        logger.warning("Attempting to find poppler-cpp, but pkg-config was not found.")


def warn_if_missing_tesseract() -> None:
    """
    Warns user if he misses a tesseract dependency
    """
    try:
        if not pkgconfig.installed("tesseract", ">=5.0.0"):
            logger.warning(
                "Attempting to run pipeline with pdf->txt conversion, that requires tesseract, but tesseract was not found."
            )
    except OSError:
        logger.warning("Attempting to find tesseract, but pkg-config was not found.")


def choose_lowest_eal(eals: set[str] | None) -> str | None:
    """
    Given a set of EAL strings, chooses the lowest one.
    """
    if not eals:
        return None

    matches = [(re.search(r"\d+", x)) for x in eals]
    min_number = min([int(x.group()) for x in matches if x])
    candidates = [x for x in eals if str(min_number) in x]
    return "EAL" + str(min_number) if len(candidates) == 2 else candidates[0]
