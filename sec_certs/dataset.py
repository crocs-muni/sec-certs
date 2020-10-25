from .meta_parser import CCMetaParser
from .certificate import CommonCriteriaCert
from . import constants


class Dataset:
    def __init__(self, certs, framework, data_dir, name='dataset name', description='dataset_description'):
        self.certs = certs
        self.framework = framework
        self.data_dir = data_dir

        self.sha256_digest = 'not implemented'  # TODO: Implement as hash of all certs
        self.name = name  # TODO: Allow for naming of the datasets
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

    def dump_to_json(self):
        pass

    # Not sure if we're going to implement
    def dump_to_csv(self):
        pass

    # Not sure if we want such behaviour
    def __eq__(self, other):
        return self.certs == other.certs

    def __str__(self):
        return 'Not implemented'  # TODO: Prepare some meaningful representation of the dataset

    @classmethod
    def init_from_meta(cls, data_dir, name, description):
        pass


class CCDataset(Dataset):
    @classmethod
    def init_from_meta(cls, data_dir, name, description):
        parser = CCMetaParser()
        records = parser.parse_meta()
        certs = {}

        for r in records:
            cert = CommonCriteriaCert.from_dict(r)
            certs[cert.sha256] = cert

        return CCDataset(certs, constants.CertFramework.CC, data_dir, name, description)


class FIPSDataset(Dataset):
    pass
