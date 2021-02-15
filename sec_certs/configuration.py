import yaml
from pathlib import Path

class Configuration:
    def load(self, path: Path):
        with open(path, 'r') as file:
            state = yaml.load(file, Loader=yaml.FullLoader)
        for k, v in state.items():
            setattr(self, k, v)

config = Configuration()