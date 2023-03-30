from tqdm import tqdm as tqdm_original

from sec_certs.configuration import config


def tqdm(*args, **kwargs):
    if "disable" in kwargs:
        return tqdm_original(*args, **kwargs)
    return tqdm_original(*args, **kwargs, disable=not config.enable_progress_bars)
