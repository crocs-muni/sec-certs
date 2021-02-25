from tqdm import tqdm
from multiprocessing.pool import Pool, ThreadPool
from typing import Callable, Iterable, Optional
import time


def process_parallel(func: Callable, items: Iterable, max_workers: int, callback: Optional[Callable] = None,
                     use_threading: bool = True, progress_bar: bool = True, unpack: bool = False):
    if use_threading is True:
        pool = ThreadPool(max_workers)
    else:
        pool = Pool(max_workers)

    if unpack is False:
        results = [pool.apply_async(func, (i, ), callback=callback) for i in items]
    else:
        results = [pool.apply_async(func, (*i, ), callback=callback) for i in items]

    if progress_bar is True:
        bar = tqdm(total=len(results))
        while not all([x.ready() for x in results]):
            done_count = len([x.ready() for x in results if x.ready()])
            bar.update(done_count - bar.n)
            time.sleep(1)
        bar.update(len(results) - bar.n)
        bar.close()

    pool.close()
    pool.join()

    return [r.get() for r in results]
