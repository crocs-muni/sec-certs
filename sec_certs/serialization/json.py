import copy
import json
from datetime import date
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union


class ComplexSerializableType:
    # Ideally, the serialized_fields would be an class variable referencing itself, but that it virtually impossible
    # to achieve without using metaclasses. Not to complicate the code, we choose instance variable.
    @property
    def serialized_attributes(self) -> List[str]:
        if hasattr(self, "__slots__") and self.__slots__:
            return list(self.__slots__)
        return list(self.__dict__.keys())

    def to_dict(self):
        if hasattr(self, "__slots__") and self.__slots__:
            return {
                key: copy.deepcopy(getattr(self, key)) for key in self.__slots__ if key in self.serialized_attributes
            }
        return {key: val for key, val in copy.deepcopy(self.__dict__).items() if key in self.serialized_attributes}

    @classmethod
    def from_dict(cls, dct: Dict):
        try:
            return cls(**dct)
        except TypeError as e:
            raise TypeError(f"Dict: {dct} on {cls.__mro__}") from e

    def to_json(self, output_path: Optional[Union[str, Path]] = None):
        if output_path is None and not hasattr(self, "json_path"):
            raise ValueError(
                f"The object {self} of type {self.__class__} does not have json_path attribute but to_json() was called without an argument."
            )
        elif output_path is None and self.json_path is None:  # type: ignore
            raise ValueError(
                f"The object {self} of type {self.__class__} does not have json_path attribute but to_json() was called without an argument."
            )
        elif output_path is None:
            output_path = self.json_path  # type: ignore
        with Path(output_path).open("w") as handle:
            json.dump(self, handle, indent=4, cls=CustomJSONEncoder, ensure_ascii=False)

    @classmethod
    def from_json(cls, input_path: Union[str, Path]):
        input_path = Path(input_path)
        with input_path.open("r") as handle:
            obj = json.load(handle, cls=CustomJSONDecoder)
        return obj


# Decorator for serialization
def serialize(func: Callable):
    def inner_func(*args, **kwargs):
        if not args or not issubclass(type(args[0]), ComplexSerializableType):
            raise ValueError(
                "@serialize decorator is to be used only on instance methods of ComplexSerializableType child classes."
            )

        update_json = kwargs.pop("update_json", True)
        result = func(*args, **kwargs)
        if update_json:
            args[0].to_json()
        return result

    return inner_func


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ComplexSerializableType):
            return {**{"_type": type(obj).__name__}, **obj.to_dict()}
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, frozenset):
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
        if "_type" in obj and obj["_type"] in self.serializable_complex_types.keys():
            complex_type = obj.pop("_type")
            return self.serializable_complex_types[complex_type].from_dict(obj)

        return obj

    # TODO: Check if sets are deserialized as sets
