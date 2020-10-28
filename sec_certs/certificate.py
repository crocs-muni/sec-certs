from typing import Type
import json
from abc import ABC, abstractmethod
from . import constants as constants


class CertificateJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Certificate):
            return obj.to_dict()
        return super().default(obj)


class Certificate(ABC):
    def __init__(self):
        self.sha256 = None

    def __repr__(self):
        return str(self.to_dict())

    def __str__(self):
        return 'Not implemented'

    @abstractmethod
    def to_dict(self):
        raise NotImplementedError('Not meant to be implemented')

    def __eq__(self, other: 'Certificate') -> bool:
        return self.sha256 == other.sha256

    @classmethod
    @abstractmethod
    def from_dict(cls, dct):
        raise NotImplementedError('Mot meant to be implemented')


class CommonCriteriaCert(Certificate):
    def to_dict(self):
        pass

    @classmethod
    def from_dict(cls, dct):
        return CommonCriteriaCert()


class FIPSCertificate(Certificate):
    def to_dict(self):
        pass

    @classmethod
    def from_dict(cls, dct):
        return FIPSCertificate()
