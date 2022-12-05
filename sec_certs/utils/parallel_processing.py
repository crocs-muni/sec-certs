from __future__ import annotations

import time
from multiprocessing.pool import ThreadPool
from typing import Any, Callable, Iterable

from billiard.pool import Pool

from sec_certs.utils.tqdm import tqdm


def process_parallel(
    func: Callable,
    items: Iterable,
    max_workers: int,
    callback: Callable | None = None,
    use_threading: bool = True,
    progress_bar: bool = True,
    unpack: bool = False,
    progress_bar_desc: str | None = None,
) -> list[Any]:

    pool: Pool | ThreadPool = ThreadPool(max_workers) if use_threading else Pool(max_workers)
    results = (
        [pool.apply_async(func, (*i,), callback=callback) for i in items]
        if unpack
        else [pool.apply_async(func, (i,), callback=callback) for i in items]
    )

    if progress_bar is True and items:
        bar = tqdm(total=len(results), desc=progress_bar_desc)
        while not all(all_done := [x.ready() for x in results]):
            done_count = len(list(filter(lambda x: x, all_done)))
            bar.update(done_count - bar.n)
            time.sleep(1)
        bar.update(len(results) - bar.n)
        bar.close()

    pool.close()
    pool.join()
    pool.terminate()

    return [r.get() for r in results]
