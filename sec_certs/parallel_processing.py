from sec_certs.helpers import tqdm
from concurrent.futures import ProcessPoolExecutor as ProcessPool, ThreadPoolExecutor as ThreadPool
from typing import Callable, Iterable, Optional
import time


def process_parallel(func: Callable, items: Iterable, max_workers: int,
                     use_threading: bool = True, progress_bar: bool = True, unpack: bool = False,
                     progress_bar_desc: Optional[str] = None):

    pool: Union[Pool, ThreadPool] = ThreadPool(max_workers) if use_threading else Pool(max_workers)
    results = [pool.submit(func, *i) for i in items] if unpack else [pool.submit(func, i) for i in items]

    if progress_bar is True and items:
        bar = tqdm(total=len(results), desc=progress_bar_desc)
        while not all(all_done := [x.done() for x in results]):
            done_count = len(list(filter(lambda x: x, all_done)))
            bar.update(done_count - bar.n)
            time.sleep(1)
        bar.update(len(results) - bar.n)
        bar.close()

    pool.shutdown()

    return [r.result() for r in results]
