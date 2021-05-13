import yaml
from typing import Union, Any
from pathlib import Path
from importlib_resources import files

import sec_certs


class Configuration(object):
    # TODO: Should raise ValueError on unvalidated config
    def load(self, filepath: Union[str, Path]):
        with Path(filepath).open('r') as file:
            state = yaml.load(file, Loader=yaml.FullLoader)

        for k, v in state.items():
            setattr(self, k, v)

    def __getattribute__(self, key):
        res = object.__getattribute__(self, key)
        if isinstance(res, dict) and 'value' in res:
            return res['value']
        return object.__getattribute__(self, key)


config_path = files(sec_certs).joinpath('settings.yaml')
config = Configuration()
config.load(config_path)
