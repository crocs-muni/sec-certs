from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from multiprocessing import cpu_count
from multiprocessing.pool import Pool, ThreadPool
from typing import Any

from sec_certs.configuration import config
from sec_certs.utils.tqdm import tqdm


def get_batches(items: list, max_workers: int, min_batch_size: int) -> tuple[list[list], list[int]]:
    max_batches = max(1, len(items) // min_batch_size)
    actual_workers = min(max_batches, max_workers)
    batch_size = len(items) // actual_workers
    remainder = len(items) % actual_workers

    batches = []
    batch_sizes = []
    start = 0
    for i in range(actual_workers):
        size = batch_size + (1 if i < remainder else 0)
        batches.append(items[start : start + size])
        batch_sizes.append(size)
        start += size

    return batches, batch_sizes


def process_parallel(
    func: Callable,
    items: Iterable,
    max_workers: int = config.n_threads,
    batching: bool = False,
    min_batch_size: int = 4,
    callback: Callable | None = None,
    use_threading: bool = True,
    progress_bar: bool = True,
    unpack: bool = False,
    progress_bar_desc: str | None = None,
) -> list[Any]:
    if max_workers == -1:
        max_workers = cpu_count()

    actual_workers = max_workers
    batch_sizes: list[int] = []
    if batching:
        assert min_batch_size > 1
        unpack = False
        batches, batch_sizes = get_batches(list(items), max_workers, min_batch_size)
        actual_workers = len(batches)
        items = batches

    pool: Pool | ThreadPool = ThreadPool(actual_workers) if use_threading else Pool(actual_workers)
    results = (
        [pool.apply_async(func, (*i,), callback=callback) for i in items]
        if unpack
        else [pool.apply_async(func, (i,), callback=callback) for i in items]
    )

    if progress_bar is True and items:
        total = sum(batch_sizes) if batching else len(results)
        bar = tqdm(total=total, desc=progress_bar_desc)
        while not all(all_done := [x.ready() for x in results]):
            if batching:
                done_count = sum(batch_sizes[i] for i, ready in enumerate(all_done) if ready)
            else:
                done_count = len(list(filter(lambda x: x, all_done)))
            bar.update(done_count - bar.n)
            time.sleep(1)

        bar.update(total - bar.n)
        bar.close()

    pool.close()
    pool.join()
    pool.terminate()

    if batching:
        flattened = []
        for batch in results:
            if (batch_result := batch.get()) is not None:
                flattened.extend(batch_result)
        return flattened
    else:
        return [r.get() for r in results]
