from __future__ import annotations

import time
from collections.abc import Callable, Collection, Iterable
from functools import partial
from multiprocessing import cpu_count, get_context
from multiprocessing.pool import Pool, ThreadPool
from typing import Any

from sec_certs.configuration import config
from sec_certs.utils.tqdm import tqdm

_worker_instance: Any = None


def _init_worker_instance(instance_cls: type, instance_args: tuple) -> None:
    global _worker_instance
    _worker_instance = instance_cls(*instance_args)


def _get_worker_instance() -> Any:
    if _worker_instance is None:
        raise RuntimeError("Worker instance not initialized")
    return _worker_instance


def _worker_wrapper(item, func) -> Any:
    instance = _get_worker_instance()
    return func(item, instance)


def process_parallel_with_instance(
    instance_cls: type,
    instance_args: tuple,
    func: Callable,
    items: Collection,
    max_workers: int = config.n_threads,
    progress_bar_desc: str | None = None,
) -> list[Any]:
    if max_workers == -1:
        max_workers = cpu_count()

    ctx = get_context("spawn")
    pool = ctx.Pool(max_workers, initializer=_init_worker_instance, initargs=(instance_cls, instance_args))
    result = []
    with pool:
        wrapper = partial(_worker_wrapper, func=func)
        iterator = pool.imap_unordered(wrapper, items)
        for processed in tqdm(iterator, total=len(items), desc=progress_bar_desc):
            result.append(processed)

    return result


def process_parallel(
    func: Callable,
    items: Iterable,
    max_workers: int = config.n_threads,
    callback: Callable | None = None,
    use_threading: bool = True,
    progress_bar: bool = True,
    unpack: bool = False,
    progress_bar_desc: str | None = None,
) -> list[Any]:
    if max_workers == -1:
        max_workers = cpu_count()

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
