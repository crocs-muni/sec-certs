from sec_certs.helpers import tqdm
from multiprocessing.pool import Pool, ThreadPool
from typing import Callable, Iterable, Optional
import time


def process_parallel(func: Callable, items: Iterable, max_workers: int, callback: Optional[Callable] = None,
                     use_threading: bool = True, progress_bar: bool = True, unpack: bool = False,
                     progress_bar_desc: Optional[str] = None):

    pool = ThreadPool(max_workers) if use_threading else Pool(max_workers)
    results = [pool.apply_async(func, (*i,), callback=callback) for i in items] if unpack else [pool.apply_async(func, (i, ), callback=callback) for i in items]

    if progress_bar is True and items:
        bar = tqdm(total=len(results), desc=progress_bar_desc)
        while not all([x.ready() for x in results]):
            done_count = len([x.ready() for x in results if x.ready()])
            bar.update(done_count - bar.n)
            time.sleep(1)
        bar.update(len(results) - bar.n)
        bar.close()

    pool.close()
    pool.join()

    return [r.get() for r in results]
