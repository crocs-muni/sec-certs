from __future__ import annotations

import itertools
import logging
import math
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from multiprocessing import cpu_count
from typing import Any, Final, Generic, TypeVar

import numpy as np
import requests
from requests import RequestException, Response

from sec_certs import constants
from sec_certs.dataset.cpe import CPEDataset
from sec_certs.dataset.cve import CVEDataset
from sec_certs.utils.parallel_processing import process_parallel

logger = logging.getLogger(__name__)

DatasetType = TypeVar("DatasetType", CPEDataset, CVEDataset, dict)


@dataclass
class NvdDatasetBuilder(Generic[DatasetType], ABC):
    """
    Abstract class to build new, or enrich existing, datasets with data from NVD, using their API.
    Example:
    ```
    with CpeNvdDatasetBuilder(api_key=config.nvd_api_key) as builder:
        cpe_dataset = builder.build_dataset()
    ```
    """

    api_key: str | None = None
    n_threads: int = -1
    max_attempts: int = 5

    _start_mod_date: datetime | None = field(init=False)
    _end_mod_date: datetime | None = field(init=False)
    _ok_responses: list[requests.Response] = field(init=False, default_factory=list)
    _requests_to_process: list[tuple] = field(init=False, default_factory=list)
    _attempts_left: int = field(init=False)

    def __post_init__(self):
        self.clear_state()
        if not self.api_key:
            logger.warning("No API key for NVD database was set, the ratelimit is just 5 requests per 30 seconds.")

    def __enter__(self) -> NvdDatasetBuilder:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.clear_state()

    @property
    @abstractmethod
    def _RESULTS_PER_PAGE(self):
        """
        Specifies "resultsPerPage" parameter to the API
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def _ENDPOINT(self):
        """
        Specifies the endpoint, used mostly for logging
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def _ENDPOINT_URL(self):
        """
        Specifies the URL to send the requests to
        """
        raise NotImplementedError

    def _get_last_update_from_previous_data(self, dataset: DatasetType) -> datetime:
        """
        Will retrieve timestamp of the last update from the dataset.
        """
        raise NotImplementedError

    @staticmethod
    def _init_new_dataset() -> DatasetType:
        """
        Will initialize new empty dataset.
        """
        raise NotImplementedError

    def _process_responses(self, responses: list[Response], dataset_to_fill: DatasetType) -> DatasetType:
        """
        Will process the responses, construct objects and fill the `dataset_to_fill`
        """
        raise NotImplementedError

    @property
    def _actual_n_threads(self) -> int:
        if self.n_threads == -1:
            return cpu_count()
        return self.n_threads

    @property
    def base_params(self) -> dict[str, Any]:
        dct = {"resultsPerPage": self._RESULTS_PER_PAGE}

        if self._start_mod_date and self._end_mod_date:
            dct["startModDate"] = self._start_mod_date.isoformat()
            dct["endModDate"] = self._end_mod_date.isoformat()

        return dct

    @property
    def headers(self) -> dict[str, Any] | None:
        dct = {"content-type": "application/json", "User-Agent": "sec-certs"}
        if self.api_key:
            dct["apiKey"] = self.api_key
        return dct

    @property
    def _base_delay(self) -> int:
        return 2 if self.api_key else 20

    @staticmethod
    def fetch_nvd_api(
        url: str, params: dict[str, Any], headers: dict[str, Any] | None, delay: float = 0
    ) -> requests.Response:
        time.sleep(delay)
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=constants.REQUEST_TIMEOUT,
            )
        except requests.exceptions.Timeout:
            response = requests.Response()
            response.status_code = 403
        except Exception:
            response = requests.Response()
            response.status_code = 500
        return response

    def clear_state(self) -> None:
        """
        Clears the internal state of the NvdDatasetBuilder. Try to avoid calling this method. Instead, use the class in
        with statement: `with NvdDatasetBuilder(args) as fetcher: ...`
        """
        self._start_mod_date = None
        self._end_mod_date = None
        self._ok_responses = []
        self._requests_to_process = []
        self._attempts_left = self.max_attempts

    def _fill_in_mod_dates(self, force_full_update: bool, last_update: datetime) -> None:
        """
        Decides how to set date arguments in the requests. Effectively this resolves whether the update will be full
        or incremental.

        :param bool force_full_update: If set to True, will always fetch all data
        :param datetime last_update: Timestamp of the last update.
        """
        if force_full_update:
            self._start_mod_date = None
            self._end_mod_date = None
        else:
            current_timestamp = datetime.now()
            # TOCTOU ignored
            if (current_timestamp - last_update).days >= constants.INCREMENTAL_NVD_UPDATE_MAX_INTERVAL_DAYS:
                self._start_mod_date = None
                self._end_mod_date = None
                logger.info(
                    f"Will fetch complete {self._ENDPOINT} data from NVD API as the last update was either done >120 days ago, or no previous data was provided."
                )
            else:
                self._start_mod_date = last_update
                self._end_mod_date = current_timestamp

    def _get_n_total_results(self, fresh: bool = True) -> int:
        if not fresh:
            time.sleep(6)

        response = NvdDatasetBuilder.fetch_nvd_api(
            self._ENDPOINT_URL, params={**self.base_params, **{"resultsPerPage": 0}}, headers=self.headers
        )
        if response.status_code == 404:
            # This is likely due to no CPEs to update, incremental update very soon.
            return 0
        if response.status_code != constants.RESPONSE_OK:
            if fresh:
                logger.warning(
                    f"Error when attempting to fetch number of pages to get from NVD API {self._ENDPOINT} endpoint, sleeping 6 seconds and repeating."
                )
                return self._get_n_total_results(fresh=False)
            else:
                logger.error(
                    f"Could not fetch the number of pages to get from NVD API {self._ENDPOINT} endpoint even after retry attempt, raising exception."
                )
                raise RequestException(
                    f"Could not fetch the number of pages to get from NVD API {self._ENDPOINT} endpoint even after retry attempt"
                )
        return response.json()["totalResults"]

    def _build_arguments(self) -> None:
        """
        Makes an API call to NVD API to learn how many records in total will be fetch. Based on that, prepares
        a list of tuples that parametrize the requests to be made.
        """
        n_requests = math.ceil(self._get_n_total_results() / self._RESULTS_PER_PAGE)
        logger.info(
            f"Building arguments for NVD requests to {self._ENDPOINT} endpoint. Will send {n_requests} requests."
        )
        offsets = [i * self._RESULTS_PER_PAGE for i in range(n_requests)]
        delays = [self._base_delay * random.randint(1, 3) for _ in range(n_requests)]  # Bulgarian constant
        self._requests_to_process = [
            (self._ENDPOINT_URL, {**self.base_params, **{"startIndex": offset}}, self.headers, delay)
            for offset, delay in zip(offsets, delays)
        ]

    def _evaluate_responses(self, responses: list[Response]) -> None:
        """
        Will fetch successfull responses into self._ok_responses and prune self.requests_to_process accordingly
        """
        response_is_nok = np.array([x.status_code != constants.RESPONSE_OK for x in responses])
        nok_indices = np.where(response_is_nok == True)[0]  # noqa E712, doesn't work with `is True`
        currently_ok = [x for x in responses if x.status_code == constants.RESPONSE_OK]

        logger.info(
            f"Attempt {self.max_attempts - self._attempts_left}/{self.max_attempts}: Successfully processed {len(currently_ok)}/{len(self._requests_to_process)} requests."
        )

        self._ok_responses.extend(currently_ok)
        self._requests_to_process = [self._requests_to_process[x] for x in nok_indices]

        if self._attempts_left == 0 and self._requests_to_process:
            logger.warning(
                f"Failed to process {len(self._requests_to_process)} requests in total, the dataset will be incomplete."
            )

    def _request_parallel_and_handle_responses(self):
        """
        Attempts to fetch the requests in the queue multiple times, and in parallel
        """
        if self._attempts_left > 0 and self._requests_to_process:
            self._attempts_left -= 1
            self._evaluate_responses(
                process_parallel(
                    NvdDatasetBuilder.fetch_nvd_api,
                    self._requests_to_process,
                    max_workers=self._actual_n_threads,
                    unpack=True,
                    progress_bar_desc=f"Fetching data from {self._ENDPOINT} NVD endpoint",
                )
            )
            self._request_parallel_and_handle_responses()

    def build_dataset(self, dataset_to_fill: DatasetType | None = None, force_full_update: bool = False) -> DatasetType:
        """
        Will fetch the resource in a parallelized fashion. If possible, use this within a with statement.
        E.g., `with NvdDatasetBuilder(args) as builder: builder.build_dataset()`
        When used outside of the context manager, the caller is responsible for cleaning the state with
        `self.clear_state()` after running this method.

        :param DatasetType | None dataset_to_fill: Existing dataset to fill-in with new data, defaults to None
        :param bool force_full_update: If True, will always fetch all data, defaults to False
        :return DatasetType: Dataset enriched with the new records from NVD.
        """
        if dataset_to_fill is None:
            dataset_to_fill = self._init_new_dataset()

        last_update = self._get_last_update_from_previous_data(dataset_to_fill)
        self._fill_in_mod_dates(force_full_update, last_update)
        self._build_arguments()
        self._request_parallel_and_handle_responses()

        return self._process_responses(self._ok_responses, dataset_to_fill)


class CpeNvdDatasetBuilder(NvdDatasetBuilder[CPEDataset]):
    _ENDPOINT: Final[str] = "CPE"
    _ENDPOINT_URL: Final[str] = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    _RESULTS_PER_PAGE: Final[int] = 10000

    def _process_responses(self, responses: list[requests.Response], cpe_dataset: CPEDataset) -> CPEDataset:
        products = list(itertools.chain.from_iterable(response.json()["products"] for response in responses))
        timestamp = self._end_mod_date.isoformat() if self._end_mod_date else responses[-1].json()["timestamp"]
        cpe_dataset.enhance_with_nvd_data({"timestamp": timestamp, "products": products})
        return cpe_dataset

    def _get_last_update_from_previous_data(self, previous_data: CPEDataset) -> datetime:
        return previous_data.last_update_timestamp

    @staticmethod
    def _init_new_dataset() -> CPEDataset:
        return CPEDataset()


class CveNvdDatasetBuilder(NvdDatasetBuilder[CVEDataset]):
    _ENDPOINT: Final[str] = "CVE"
    _ENDPOINT_URL: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _RESULTS_PER_PAGE: Final[int] = 2000

    def _process_responses(self, responses: list[Response], cve_dataset: CVEDataset) -> CVEDataset:
        timestamp = self._end_mod_date.isoformat() if self._end_mod_date else responses[-1].json()["timestamp"]
        vulns = list(itertools.chain.from_iterable(response.json()["vulnerabilities"] for response in responses))
        cve_dataset.enhance_with_nvd_data({"timestamp": timestamp, "vulnerabilities": vulns})
        return cve_dataset

    def _get_last_update_from_previous_data(self, previous_data: CVEDataset) -> datetime:
        return previous_data.last_update_timestamp

    @staticmethod
    def _init_new_dataset() -> CVEDataset:
        return CVEDataset()


class CpeMatchNvdDatasetBuilder(NvdDatasetBuilder[dict]):
    _ENDPOINT: Final[str] = "CPEMatch"
    _ENDPOINT_URL: Final[str] = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
    _RESULTS_PER_PAGE: Final[int] = 5000
    _VERSION_KEYS: Final[list[str]] = [
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    ]

    def _process_responses(self, responses: list[Response], dataset_to_fill: dict) -> dict:
        timestamp = self._end_mod_date.isoformat() if self._end_mod_date else responses[-1].json()["timestamp"]
        match_strings = list(itertools.chain.from_iterable(response.json()["matchStrings"] for response in responses))
        dataset_to_fill["timestamp"] = timestamp

        inactive_criteria = set()
        for m in match_strings:
            if m["matchString"]["status"] == "Inactive":
                inactive_criteria.add(m["matchString"]["matchCriteriaId"])
            else:
                if "matches" in m["matchString"]:
                    dataset_to_fill["match_strings"][m["matchString"]["matchCriteriaId"]] = {
                        "criteria": m["matchString"]["criteria"],
                        "matches": m["matchString"]["matches"],
                    }
                    for version_key in self._VERSION_KEYS:
                        if version_key in m["matchString"]:
                            dataset_to_fill["match_strings"][m["matchString"]["matchCriteriaId"]][version_key] = m[
                                "matchString"
                            ][version_key]

        for inactive in inactive_criteria:
            dataset_to_fill["match_strings"].pop(inactive, None)

        return dataset_to_fill

    def _get_last_update_from_previous_data(self, previous_data: dict) -> datetime:
        return datetime.fromisoformat(previous_data["timestamp"])

    @staticmethod
    def _init_new_dataset() -> dict:
        return {"timestamp": datetime.fromtimestamp(0).isoformat(), "match_strings": {}}
