from typing import Type
import json


# TODO: Move me to appropriate place. I'm here just to demonstrate how we're going to serialize to json
class CertificateJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Certificate):
            return obj.asdict()
        return super().default(obj)


class Certificate:
    def __init__(self):
        self.sha256 = None
        self.framework = None  # CC or FIPS or PP or whatever
        self.product_name = None
        self.vendor_name = None
        self.pdf_path = None

    def __repr__(self):
        return str(self.asdict())

    def __str__(self):
        return 'Not implemented'  # TODO: Introduce some meaningful representation of the certificate

    def asdict(self):
        return {'not': 'implemented'}  # TODO: Implement me, I'll be used for json serialization!

    def __eq__(self, other: 'Certificate') -> bool:
        return self.sha256 == other.sha256

    @classmethod
    def from_dict(cls, dct):
        raise NotImplementedError('Mot meant to be implemented')


class CommonCriteriaCert(Certificate):
    @classmethod
    def from_dict(cls, dct):
        return CommonCriteriaCert()


class FIPSCertificate(Certificate):
    @classmethod
    def from_dict(cls, dct):
        return FIPSCertificate()
