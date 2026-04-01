from __future__ import annotations

import pytest

from sec_certs.utils.parallel_processing import process_parallel


def _add(a: int, b: int) -> int:
    return a + b


def _multiply(x: int, factor: int = 1) -> int:
    return x * factor


def _add_and_multiply(a: int, b: int, factor: int = 1) -> int:
    return (a + b) * factor


def _identity(x):
    return x


def test_process_parallel_basic():
    results = process_parallel(_identity, [1, 2, 3], progress_bar=False)
    assert results == [1, 2, 3]


def test_process_parallel_unpack():
    items = [(1, 2), (3, 4), (10, 20)]
    results = process_parallel(_add, items, unpack=True, progress_bar=False)
    assert results == [3, 7, 30]


def test_process_parallel_kwargs():
    results = process_parallel(_multiply, [2, 3, 5], kwargs={"factor": 10}, progress_bar=False)
    assert results == [20, 30, 50]


def test_process_parallel_unpack_with_kwargs():

    items = [(1, 2), (3, 4)]
    results = process_parallel(_add_and_multiply, items, kwargs={"factor": 3}, unpack=True, progress_bar=False)
    assert results == [9, 21]


def test_process_parallel_callback():
    collected: list[int] = []

    def _on_result(result):
        collected.append(result)

    process_parallel(_identity, [10, 20, 30], callback=_on_result, progress_bar=False)
    assert collected == [10, 20, 30]


def test_process_parallel_empty_items():
    results = process_parallel(_identity, [], progress_bar=False)
    assert results == []


@pytest.mark.parametrize("use_threading", [True, False])
def test_process_parallel_threading_and_multiprocessing(use_threading: bool):
    results = process_parallel(
        _multiply, [1, 2, 3], kwargs={"factor": 5}, use_threading=use_threading, progress_bar=False
    )
    assert results == [5, 10, 15]
