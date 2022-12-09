from abc import ABC, abstractmethod


class PandasSerializableType(ABC):
    def __init__(self, *args, **kwargs):
        pass

    @property
    @abstractmethod
    def pandas_tuple(self):
        raise NotImplementedError("Not meant to be implemented")

    @property
    @abstractmethod
    def pandas_columns(self):
        raise NotImplementedError("Not meant to be implemented")
