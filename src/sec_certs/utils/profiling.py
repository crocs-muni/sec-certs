import gc
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from logging import Logger

import psutil


@contextmanager
def log_stage(logger: Logger, msg: str, collect_garbage: bool = False):
    """Contextmanager that logs a message to the logger when it is entered and exited.
    The message has debug information about memory use. Optionally, it can
    run garbage collection when exiting.
    """
    meminfo = psutil.Process().memory_full_info()
    logger.info(f">> Starting >> {msg}")
    logger.debug(str(meminfo))
    start_time = datetime.now()

    try:
        yield
    finally:
        end_time = datetime.now()
        duration = end_time - start_time
        meminfo = psutil.Process().memory_full_info()
        logger.info(f"<< Finished << {msg} ({duration})")
        logger.debug(str(meminfo))

        if collect_garbage:
            gc.collect()


def staged(logger: Logger, log_message: str, collect_garbage: bool = False):
    """Like log_stage but a decorator."""

    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with log_stage(logger, log_message, collect_garbage):
                return func(*args, **kwargs)

        return wrapper

    return deco
