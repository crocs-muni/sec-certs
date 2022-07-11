import hashlib
import logging
import re
import time
from contextlib import nullcontext
from datetime import datetime
from functools import partial
from multiprocessing.pool import ThreadPool
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

import numpy as np
import pkgconfig
import requests
from tqdm import tqdm as tqdm_original

import sec_certs.constants as constants
from sec_certs.config.configuration import config

logger = logging.getLogger(__name__)


# TODO: Once typehints in tqdm are implemented, we should use them: https://github.com/tqdm/tqdm/issues/260
def tqdm(*args, **kwargs):
    if "disable" in kwargs:
        return tqdm_original(*args, **kwargs)
    return tqdm_original(*args, **kwargs, disable=not config.enable_progress_bars)


def download_file(
    url: str, output: Path, delay: float = 0, show_progress_bar: bool = False, progress_bar_desc: Optional[str] = None
) -> Union[str, int]:
    try:
        time.sleep(delay)
        # See https://github.com/psf/requests/issues/3953 for header justification
        r = requests.get(
            url, allow_redirects=True, timeout=constants.REQUEST_TIMEOUT, stream=True, headers={"Accept-Encoding": None}  # type: ignore
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
            with ctx() as pbar:
                with output.open("wb") as f:
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


def download_parallel(items: Sequence[Tuple[str, Path]], num_threads: int) -> Sequence[Tuple[str, int]]:
    def download(url_output):
        url, output = url_output
        return url, download_file(url, output)

    pool = ThreadPool(num_threads)
    responses = []
    with tqdm(total=len(items)) as progress:
        for response in pool.imap(download, items):
            progress.update(1)
            responses.append(response)
    pool.close()
    pool.join()
    return responses


def fips_dgst(cert_id: Union[int, str]) -> str:
    return get_first_16_bytes_sha256(str(cert_id))


def get_first_16_bytes_sha256(string: str) -> str:
    return hashlib.sha256(string.encode("utf-8")).hexdigest()[:16]


def get_sha256_filepath(filepath: Union[str, Path]) -> str:
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
    timestamp = timestamp.replace(tzinfo=None)
    return timestamp


def is_in_dict(target_dict: Dict, path: str) -> bool:
    current_level = target_dict
    for item in path:
        if item not in current_level:
            return False
        else:
            current_level = current_level[item]
    return True


def compute_heuristics_version(cert_name: str) -> Set[str]:
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


def tokenize_dataset(dset: List[str], keywords: Set[str]) -> np.ndarray:
    return np.array([tokenize(x, keywords) for x in dset])


def tokenize(string: str, keywords: Set[str]) -> str:
    return " ".join([x for x in string.split() if x.lower() in keywords])


# Credit: https://stackoverflow.com/questions/18092354/
def split_unescape(s: str, delim: str, escape: str = "\\", unescape: bool = True) -> List[str]:
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
    except EnvironmentError:
        logger.warning("Attempting to find poppler-cpp, but pkg-config was not found.")


def warn_if_missing_graphviz() -> None:
    """
    Warns user if he misses a graphviz dependency
    """
    try:
        if not pkgconfig.installed("libcgraph", ">=2.0.0"):
            logger.warning("Attempting to run pipeline that requires graphviz, but graphviz was not found.")
    except EnvironmentError:
        logger.warning("Attempting to find graphviz, but pkg-config was not found.")


def warn_if_missing_tesseract() -> None:
    """
    Warns user if he misses a tesseract dependency
    """
    try:
        if not pkgconfig.installed("tesseract", ">=5.0.0"):
            logger.warning(
                "Attempting to run pipeline with pdf->txt conversion, that requires tesseract, but tesseract was not found."
            )
    except EnvironmentError:
        logger.warning("Attempting to find tesseract, but pkg-config was not found.")
