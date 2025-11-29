import json
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps

import dramatiq
import sentry_sdk
from dramatiq import Retry
from dramatiq.common import compute_backoff
from dramatiq.middleware import CurrentMessage
from dramatiq.middleware.retries import DEFAULT_MAX_BACKOFF, DEFAULT_MIN_BACKOFF
from redis.exceptions import LockNotOwnedError
from redis.lock import Lock

from ... import redis

logger = logging.getLogger(__name__)


def no_simultaneous_execution(lock_name: str, abort: bool = False, timeout: float = 60 * 10):  # pragma: no cover
    """
    A decorator that prevents simultaneous execution of more than one actor.

    :param lock_name:
    :param abort: Whether to abort task if lock cannot be acquired immediately.
    :param timeout: Lock timeout (in seconds). The lock will be automatically released after.
    :return:
    """

    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            msg = CurrentMessage.get_current_message()
            if msg is None:
                # If we are testing and not in a worker, just execute
                return f(*args, **kwargs)
            lock: Lock = redis.lock(lock_name, timeout=timeout)
            acq = lock.acquire(blocking=not abort)
            if not acq:
                logger.warning(f"Failed to acquire lock: {lock_name}")
                return
            try:
                return f(*args, **kwargs)
            finally:
                try:
                    lock.release()
                except LockNotOwnedError:
                    logger.warning(f"Releasing lock late: {lock_name}")

        return wrapper

    return deco


def single_queue(queue_name: str, timeout: float = 60 * 10):  # pragma: no cover
    """
    A decorator that prevents simultaneous execution of more than one actor in a queue.
    It does so by requeueing the actor.
    """

    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            msg = CurrentMessage.get_current_message()
            if msg is None:
                # If we are testing and not in a worker, just execute
                return f(*args, **kwargs)
            retries = msg.options.get("retries", 0)
            lock: Lock = redis.lock(queue_name, timeout=timeout)
            acq = lock.acquire(blocking=False)
            if not acq:
                _, delay = compute_backoff(retries, factor=DEFAULT_MIN_BACKOFF, max_backoff=DEFAULT_MAX_BACKOFF)
                raise Retry(message=f"Failed to acquire queue lock: {queue_name}", delay=delay)
            try:
                return f(*args, **kwargs)
            finally:
                try:
                    lock.release()
                except LockNotOwnedError:
                    logger.warning(f"Releasing queue lock late: {queue_name}")

        return wrapper

    return deco


def task(task_name):
    """
    A decorator that logs task start and end times to Redis.
    """

    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            msg = CurrentMessage.get_current_message()
            if msg is None:
                # If we are testing and not in a worker, just execute
                return f(*args, **kwargs)
            with sentry_sdk.start_transaction(op="dramatiq", name=task_name):
                tid = secrets.token_hex(16)
                start = datetime.now()
                data = {"name": task_name, "start_time": start.isoformat()}
                logger.info(f'Starting task ({task_name}), tid="{tid}"')
                redis.set(tid, json.dumps(data))
                redis.sadd("tasks", tid)
                try:
                    return f(*args, **kwargs)
                finally:
                    logger.info(f'Ending task ({task_name}), tid="{tid}", took {datetime.now() - start}')
                    redis.srem("tasks", tid)
                    redis.delete(tid)

        return wrapper

    return deco


def actor(name: str, lock_name: str, queue_name: str, timeout: timedelta):
    """
    Usual dramatiq actor setup.
    """

    def deco(f):
        @wraps(f)
        @dramatiq.actor(
            actor_name=name,
            queue_name=queue_name,
            max_retries=0,
            retry_when=lambda retries, exc: isinstance(exc, Retry),
            time_limit=timeout.total_seconds() * 1000,
        )
        @no_simultaneous_execution(lock_name, abort=True, timeout=(timeout + timedelta(minutes=10)).total_seconds())
        @single_queue(queue_name, timeout=(timeout + timedelta(minutes=10)).total_seconds())
        @task(name)
        def wrapper(*args, **kwargs):
            return f(*args, **kwargs)

        return wrapper

    return deco
