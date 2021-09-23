import yaml
from typing import Union, Any
from pathlib import Path
from importlib_resources import files
import jsonschema
import json
import os

import sec_certs


class Configuration(object):
    def load(self, filepath: Union[str, Path]):
        with Path(filepath).open('r') as file:
            state = yaml.load(file, Loader=yaml.FullLoader)

        script_dir = Path(__file__).parent

        with open(Path(script_dir) / 'settings-schema.json', 'r') as file:
            schema = json.loads(file.read())

        jsonschema.validate(state, schema)

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
