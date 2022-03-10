import json
from pathlib import Path
from typing import Any, Union

import jsonschema
import yaml


class Configuration(object):
    def load(self, filepath: Union[str, Path]) -> None:
        with Path(filepath).open("r") as file:
            state = yaml.load(file, Loader=yaml.FullLoader)

        script_dir = Path(__file__).parent

        with (Path(script_dir) / "settings-schema.json").open("r") as file:
            schema = json.loads(file.read())

        try:
            jsonschema.validate(state, schema)
        except jsonschema.exceptions.ValidationError as e:
            print(f"{e}\n\nIn file {filepath}")

        for k, v in state.items():
            setattr(self, k, v)

    def __getattribute__(self, key: str) -> Any:
        res = object.__getattribute__(self, key)
        if isinstance(res, dict) and "value" in res:
            return res["value"]
        return object.__getattribute__(self, key)


DEFAULT_CONFIG_PATH = Path(__file__).parent / "settings.yaml"
config = Configuration()
config.load(DEFAULT_CONFIG_PATH)
