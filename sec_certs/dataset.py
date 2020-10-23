class Dataset:
    def __init__(self):
        self.certs = {}
        self.framework = None
        self.data_dir = None

        self.sha256_digest = 'not implemented'  # TODO: Implement as hash of all certs
        self.name = 'not implemented'  # TODO: Allow for naming of the datasets
        self.description = 'not implemented'  # Allow for descriptions of the dataset

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


class DatasetCC(Dataset):
    pass


class DatasetFIPS(Dataset):
    pass
