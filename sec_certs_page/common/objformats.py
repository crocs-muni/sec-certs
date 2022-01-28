from abc import ABC
from datetime import date
from pathlib import Path

from jsondiff.symbols import Symbol
from sec_certs.serialization.json import ComplexSerializableType

from .frozendict import frozendict

_sct = None


def serializable_complex_types():
    global _sct
    if _sct is None:
        _sct = {x.__name__: x for x in ComplexSerializableType.__subclasses__()}
    return _sct


class Format(ABC):
    def __init__(self, obj):
        self.obj = obj

    def get(self):
        return self.obj


class StorageFormat(Format):
    """
    The format used for storage in MongoDB.
    It is a dict with only MongoDB valid types (so no sets or dates, or Paths).
    Dictionary keys don't have dots.
    """

    def to_working_format(self) -> "WorkingFormat":
        # add sets, add dots
        def walk(obj):
            if isinstance(obj, dict):
                if "_type" in obj and obj["_type"] == "set":
                    return set(walk(obj["_value"]))
                elif "_type" in obj and obj["_type"] == "frozenset":
                    return frozenset(walk(obj["_value"]))
                elif "_type" in obj and obj["_type"] == "date":
                    return date.fromisoformat(obj["_value"])
                else:
                    res = {}
                    for key in obj.keys():
                        res[key.replace("\uff0e", ".")] = walk(obj[key])
                    return frozendict(res)
            elif isinstance(obj, list):
                return list(map(walk, obj))
            return obj

        return WorkingFormat(walk(self.obj))

    def to_json_mapping(self):
        def walk(obj):
            if isinstance(obj, dict):
                if "_type" in obj and obj["_type"] in ("set", "frozenset"):
                    return list(walk(obj["_value"]))
                elif "_type" in obj and obj["_type"] in ("Path", "date"):
                    return obj["_value"]
                else:
                    res = {}
                    for key in obj.keys():
                        res[key.replace("\uff0e", ".")] = walk(obj[key])
                    return res
            elif isinstance(obj, date):
                return str(obj)
            elif isinstance(obj, list):
                return list(map(walk, obj))
            return obj

        return walk(self.obj)


class WorkingFormat(Format):
    """
    The format used for work on the site (what is passed to templates for rendering, etc.).
    It is a dict with sets, dots in keys possible.
    Has frozendict.
    """

    def to_storage_format(self) -> "StorageFormat":
        # remove sets, remove dots
        def map_key(key):
            if isinstance(key, Symbol):
                return f"__{key.label}__"
            if not isinstance(key, str):
                return str(key)
            elif "." in key:
                return key.replace(".", "\uff0e")
            return key

        def walk(obj):
            if isinstance(obj, (frozendict, dict)):
                res = {}
                for key in obj.keys():
                    res[map_key(key)] = walk(obj[key])
                return res
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, set):
                return {"_type": "set", "_value": [walk(o) for o in obj]}
            elif isinstance(obj, frozenset):
                return {"_type": "frozenset", "_value": [walk(o) for o in obj]}
            elif isinstance(obj, date):
                return {"_type": "date", "_value": str(obj)}
            return obj

        return StorageFormat(walk(self.obj))

    def to_raw_format(self) -> "RawFormat":
        # add paths
        def walk(obj):
            if isinstance(obj, dict):
                if "_type" in obj and obj["_type"] == "Path":
                    return Path(obj["_value"])
                else:
                    return {key: walk(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, set):
                return set(map(walk, obj))
            elif isinstance(obj, frozenset):
                return frozenset(map(walk, obj))
            return obj

        return RawFormat(walk(self.obj))


class RawFormat(Format):
    """Has frozendict."""

    def to_working_format(self) -> "WorkingFormat":
        # remove paths
        def walk(obj):
            if isinstance(obj, frozendict):
                return frozendict({key: walk(value) for key, value in obj.items()})
            elif isinstance(obj, dict):
                return {key: walk(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, set):
                return set(map(walk, obj))
            elif isinstance(obj, frozenset):
                return frozenset(map(walk, obj))
            elif isinstance(obj, Path):
                return {"_type": "Path", "_value": str(obj)}
            return obj

        return WorkingFormat(walk(self.obj))

    def to_obj_format(self) -> "ObjFormat":
        def walk(obj):
            if isinstance(obj, (frozendict, dict)):
                res = {key: walk(value) for key, value in obj.items()}
                if "_type" in res and res["_type"] in serializable_complex_types():
                    complex_type = res.pop("_type")
                    return serializable_complex_types()[complex_type].from_dict(res)
                else:
                    return res
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, set):
                return set(map(walk, obj))
            elif isinstance(obj, frozenset):
                return frozenset(map(walk, obj))
            return obj

        return ObjFormat(walk(self.obj))


class ObjFormat(Format):
    """No more frozendict just objects."""

    def to_raw_format(self) -> "RawFormat":
        def walk(obj):
            if isinstance(obj, ComplexSerializableType):
                return frozendict({"_type": type(obj).__name__, **walk(obj.to_dict())})
            elif isinstance(obj, dict):
                return frozendict({key: walk(value) for key, value in obj.items()})
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, set):
                return set(map(walk, obj))
            elif isinstance(obj, frozenset):
                return frozenset(map(walk, obj))
            return obj

        return RawFormat(walk(self.obj))


def load(doc):
    return StorageFormat(doc).to_working_format().get()


def store(doc):
    return WorkingFormat(doc).to_storage_format().get()
