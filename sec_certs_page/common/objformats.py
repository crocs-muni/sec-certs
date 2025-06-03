from abc import ABC
from datetime import date
from pathlib import Path

from bson.objectid import ObjectId
from jsondiff.symbols import Symbol, _all_symbols_
from sec_certs.serialization.json import ComplexSerializableType, get_class_fullname

from .frozendict import frozendict

_sct = None


def serializable_complex_types():
    global _sct
    if _sct is None:
        _sct = {get_class_fullname(x): x for x in ComplexSerializableType.__subclasses__()}
    return _sct


_symbol_map = {f"__{s.label}__": s for s in _all_symbols_}


class Format(ABC):
    def __init__(self, obj):
        self.obj = obj

    def get(self):
        return self.obj


class StorageFormat(Format):
    """
    The format used for storage in MongoDB.
    It is a dict with only MongoDB valid types (so no sets or dates, or Paths).
    Dictionary keys don't have dots (and are strings, no ints).
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
                        res[_symbol_map[key] if key in _symbol_map else key.replace("\uff0e", ".")] = walk(obj[key])
                    return frozendict(res)
            elif isinstance(obj, list):
                return list(map(walk, obj))
            return obj

        return WorkingFormat(walk(self.obj))

    def to_json_mapping(self):
        def walk(obj):
            if isinstance(obj, dict):
                if "_type" in obj and obj["_type"] in ("set", "frozenset"):
                    return {"_type": "Set", "elements": walk(obj["_value"])}
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
            elif isinstance(obj, ObjectId):
                return str(obj)
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
            # TODO: This is lossy, the type of the key is lost.
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
            elif isinstance(obj, tuple):
                return tuple(map(walk, obj))
            return obj

        return StorageFormat(walk(self.obj))

    def to_raw_format(self) -> "RawFormat":
        # add paths
        def walk(obj):
            if isinstance(obj, frozendict):
                return frozendict({key: walk(value) for key, value in obj.items()})
            elif isinstance(obj, dict):
                if "_type" in obj and obj["_type"] == "Path":
                    return Path(obj["_value"])
                else:
                    return {key: walk(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, tuple):
                return tuple(map(walk, obj))
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
            elif isinstance(obj, tuple):
                return tuple(map(walk, obj))
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
            elif isinstance(obj, tuple):
                return tuple(map(walk, obj))
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
                return frozendict({"_type": get_class_fullname(obj), **walk(obj.to_dict())})
            elif isinstance(obj, dict):
                return frozendict({key: walk(value) for key, value in obj.items()})
            elif isinstance(obj, list):
                return list(map(walk, obj))
            elif isinstance(obj, tuple):
                return tuple(map(walk, obj))
            elif isinstance(obj, set):
                return set(map(walk, obj))
            elif isinstance(obj, frozenset):
                return frozenset(map(walk, obj))
            return obj

        return RawFormat(walk(self.obj))


def load(doc):
    return StorageFormat(doc).to_working_format().get()


def freeze(doc):
    """
    Recursively "freeze" an object, turning dicts into frozendicts and sets into frozensets.

    :param doc: The object.
    :return: The frozen object.
    """

    def walk(obj):
        if isinstance(obj, dict):
            return frozendict({key: walk(value) for key, value in obj.items()})
        elif isinstance(obj, list):
            return list(map(walk, obj))
        elif isinstance(obj, tuple):
            return tuple(map(walk, obj))
        elif isinstance(obj, set):
            return set(map(walk, obj))
        elif isinstance(obj, frozenset):
            return frozenset(map(walk, obj))
        return obj

    return walk(doc)


def unfreeze(doc):
    """
    Recursively "unfreeze" an object, turning frozendicts into dicts and frozensets into sets.

    :param doc: The frozen object.
    :return: The unfrozen object.
    """

    def walk(obj):
        if isinstance(obj, frozendict):
            return {key: walk(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return list(map(walk, obj))
        elif isinstance(obj, tuple):
            return tuple(map(walk, obj))
        elif isinstance(obj, set):
            return set(map(walk, obj))
        elif isinstance(obj, frozenset):
            return set(map(walk, obj))
        return obj

    return walk(doc)


def store(doc):
    return WorkingFormat(doc).to_storage_format().get()


def cert_name(cert_doc) -> str | None:
    if name := cert_doc.get("name"):
        return name
    if web_data := cert_doc.get("web_data", cert_doc.get("web_scan")):
        if module_name := web_data.get("module_name"):
            return module_name
    return None
