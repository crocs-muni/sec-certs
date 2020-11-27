import json
from datetime import date
from pathlib import Path
from typing import Dict

from abc import ABC, abstractmethod


class ComplexSerializableType(ABC):
    @classmethod
    @abstractmethod
    def to_dict(cls):
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_dict(cls, dct: Dict):
        raise NotImplementedError


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ComplexSerializableType):
            return {**{'_type': type(obj).__name__}, **obj.to_dict()}
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, date):
            return str(obj)
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
        self.serializable_complex_types = {x.__name__: x for x in ComplexSerializableType.__subclasses__()}

    def object_hook(self, obj):
        if '_type' in obj and obj['_type'] in self.serializable_complex_types.keys():
            complex_type = obj.pop('_type')
            return self.serializable_complex_types[complex_type].from_dict(obj)

        return obj
