from jsondiff.symbols import _all_symbols_, add, delete, discard, insert, update


def _has_symbols(obj):
    def walk(o):
        if isinstance(o, dict):
            for k in o:
                if k in _all_symbols_:
                    return True
                elif walk(o[k]):
                    return True
        elif isinstance(o, (tuple, list, set)):
            for k in o:
                if walk(k):
                    return True
        return False

    return walk(obj)


def apply_explicit_diff(dct, diff):
    """
    Apply an explicit diff constructed by jsondiff.

    :param dct: The object to apply on.
    :param diff: The diff.
    :return: A new object with the diff applied.
    """

    def walk(obj, d):
        if isinstance(obj, dict):
            c = dict(obj)
            if insert in d:
                c.update(dict(d[insert]))
            if update in d:
                for k, v in d[update].items():
                    if _has_symbols(v):
                        c[k] = walk(c[k], v)
                    else:
                        c[k] = v
            if delete in d:
                for k in d[delete]:
                    del c[k]
            return c
        elif isinstance(obj, (list, tuple)):
            original_type = type(obj)
            c = list(obj)
            if delete in d:
                for pos in d[delete]:
                    c.pop(pos)
            if insert in d:
                for pos, value in d[insert]:
                    c.insert(pos, value)
            for k, v in d.items():
                if k is not delete and k is not insert:
                    k = int(k)
                    c[k] = walk(c[k], v)
            if original_type is not list:
                c = original_type(c)
            return c
        elif isinstance(obj, set):
            c = set(obj)
            if discard in d:
                for x in d[discard]:
                    c.discard(x)
            if add in d:
                for x in d[add]:
                    c.add(x)
            return c
        return obj

    return walk(dct, diff)
