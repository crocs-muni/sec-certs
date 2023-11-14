from __future__ import annotations

import copy
import gzip
import json
from collections.abc import Callable
from datetime import date, datetime
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar

from sec_certs import constants

T = TypeVar("T", bound="ComplexSerializableType")


class SerializationError(Exception):
    pass


class ComplexSerializableType:
    __slots__: tuple[str]

    def __init__(self, *args, **kwargs):
        pass

    # Ideally, the serialized_fields would be an class variable referencing itself, but that it virtually impossible
    # to achieve without using metaclasses. Not to complicate the code, we choose instance variable.
    @property
    def serialized_attributes(self) -> list[str]:
        if hasattr(self, "__slots__") and self.__slots__:
            return list(self.__slots__)
        return list(self.__dict__.keys())

    def to_dict(self) -> dict[str, Any]:
        if hasattr(self, "__slots__") and self.__slots__:
            return {
                key: copy.deepcopy(getattr(self, key)) for key in self.__slots__ if key in self.serialized_attributes
            }
        return {key: val for key, val in copy.deepcopy(self.__dict__).items() if key in self.serialized_attributes}

    @classmethod
    def from_dict(cls: type[T], dct: dict) -> T:
        try:
            return cls(**dct)
        except TypeError as e:
            raise TypeError(f"Dict: {dct} on {cls.__mro__}") from e

    def to_json(self, output_path: str | Path | None = None, compress: bool = False) -> None:
        """
        Serializes `ComplexSerializableType` instance to json file.
        :param str | Path | None output_path: path where the file will be stored. If None, `obj.json_path` access is attempted, defaults to None
        :param bool compress: if True, will be compress with gzip, defaults to False
        """
        if not output_path and (not hasattr(self, "json_path") or not self.json_path):  # type: ignore
            raise SerializationError(
                f"The object {self} of type {self.__class__} does not have json_path attribute set but to_json() was called without an argument."
            )
        if not output_path:
            output_path = self.json_path  # type: ignore
            if self.json_path == constants.DUMMY_NONEXISTING_PATH:  # type: ignore
                raise SerializationError(f"json_path attribute for '{get_class_fullname(self)}' was not yet set.")
            if hasattr(self, "root_dir") and self.root_dir == constants.DUMMY_NONEXISTING_PATH:  # type: ignore
                raise SerializationError(f"root_dir attribute for '{get_class_fullname(self)}' was not yet set.")

        if Path(output_path).is_dir():  # type: ignore
            raise SerializationError("output path for json cannot be directory.")

        # false positive MyPy warning, cannot be None
        if compress:
            with gzip.open(str(output_path), "wt", encoding="utf-8") as handle:  # type: ignore
                json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)
        else:
            with Path(output_path).open("w") as handle:  # type: ignore
                json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls: type[T], input_path: str | Path, is_compressed: bool = False) -> T:
        """
        Will load `ComplexSerializableType` from json.
        :param str | Path input_path: path to load the file from
        :param bool is_compressed: if True, will decompress .gz first, defaults to False
        :return T: the deserialized object
        """
        if is_compressed:
            with gzip.open(str(input_path), "rt", encoding="utf-8") as handle:
                return json.load(handle, cls=CustomJSONDecoder)
        else:
            with Path(input_path).open("r") as handle:
                return json.load(handle, cls=CustomJSONDecoder)


# Decorator for serialization
def serialize(func: Callable):
    @wraps(func)
    def _serialize(*args, **kwargs):
        if not args or not issubclass(type(args[0]), ComplexSerializableType):
            raise ValueError(
                "@serialize decorator is to be used only on instance methods of ComplexSerializableType child classes."
            )

        if hasattr(args[0], "_root_dir") and args[0]._root_dir == constants.DUMMY_NONEXISTING_PATH:
            raise SerializationError(
                "The invoked method requires dataset serialization. Cannot serialize without root_dir set. You can set it with obj.root_dir = ..."
            )

        update_json = kwargs.pop("update_json", True)
        result = func(*args, **kwargs)
        if update_json:
            args[0].to_json()
        return result

    return _serialize


def get_class_fullname(obj: Any) -> str:
    klass = obj if isinstance(obj, type) else obj.__class__
    module = klass.__module__
    if module == "builtins":
        return klass.__qualname__
    return module + "." + klass.__qualname__


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ComplexSerializableType):
            return {**{"_type": get_class_fullname(obj)}, **obj.to_dict()}
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, set):
            return {"_type": "Set", "elements": sorted(obj)}
        if isinstance(obj, frozenset):
            return sorted(obj)
        if isinstance(obj, date):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


class CustomJSONDecoder(json.JSONDecoder):
    """
    Custom JSONDecoder. Any complex object that should be de-serializable must inherit directly from class
    ComplexSerializableType (nested inheritance does not currently work (because x.__subclassess__() prints only direct
    subclasses. Any such class must implement methods to_dict() and from_dict(). These are used to drive serialization.
    """

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
        self.serializable_complex_types = {get_class_fullname(x): x for x in ComplexSerializableType.__subclasses__()}

    def object_hook(self, obj):
        if "_type" in obj and obj["_type"] == "Set":
            return set(obj["elements"])
        if "_type" in obj and obj["_type"] in self.serializable_complex_types:
            complex_type = obj.pop("_type")
            return self.serializable_complex_types[complex_type].from_dict(obj)
        if "_type" in obj:
            raise SerializationError(f"JSONDecoder doesn't know how to handle {obj}")

        return obj
