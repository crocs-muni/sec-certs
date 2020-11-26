from tqdm import tqdm
from multiprocessing.pool import Pool, ThreadPool
import time

# TODO: Add timeout. Kinda meh with ThreadingTimeout, SignalTimeout does not work on Windows, stopit package.
def process_parallel(func, items, max_workers, callback=None, use_threading=True, progress_bar=True):
    if use_threading is True:
        pool = ThreadPool(max_workers)
    else:
        pool = Pool(max_workers)

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