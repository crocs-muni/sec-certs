from .certificate import CommonCriteriaCert
from . import constants
from datetime import datetime


class Dataset:
    def __init__(self, certs, framework, data_dir, name='dataset name', description='dataset_description'):
        self.certs = certs
        self.framework = framework
        self.data_dir = data_dir
        self.timestamp = datetime.now()
        self.sha256_digest = 'not implemented'
        self.name = name
        self.description = description  # Allow for descriptions of the dataset

    # The idea is to iterate over dataset as: `for cert in Dataset: ... `
    def __iter__(self):
        for cert in self.certs.values():
            yield cert

    # The idea is to be able to access certificates by calling Dataset[cert_hash]
    def __getitem__(self, item):
        return self.certs.__getitem__(item.lower())

    # Same as above, but setting instead of getting
    def __setitem__(self, key, value):
        self.certs.__setitem__(key.lower(), value)

    def __len__(self):
        return len(self.certs)

    def to_json(self):
        pass

    def to_csv(self):
        pass

    def to_dataframe(self):
        pass

    @classmethod
    def from_json(cls):
        pass

    @classmethod
    def from_csv(cls):
        pass

    @classmethod
    def from_dataframe(cls, df):
        pass

    def merge(self, other):
        return self

    # Not sure if we want such behaviour
    def __eq__(self, other):
        return self.certs == other.certs

    def __str__(self):
        return 'Not implemented'





