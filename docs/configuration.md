---
file_format: mystnb
mystnb:
  remove_code_source: true
  execution_mode: 'force'
---
# Configuration

The configuration class is defined in [configuration.py](https://github.com/crocs-muni/sec-certs/tree/main/src/sec_certs/configuration.py). From CLI, you can load custom configuration yaml with `-c` or `--config` argument. From Python, you can replace the default configuration with

```python
from pathlib import Path
import sec_certs.configuration as config_module

config_module.config.load_from_yaml("/path/to/your/config.yaml")

# or just set the individual key
config_module.config.log_filepath = Path("/some/path/where/log/will/be/stored.txt")
```

The configuration yaml is a simple flat dictionary of keys and values. The configuration file can specify only *some* of the fields. For the content of unspecified fields, environment variable with `seccerts_` prefix (case insensitive) will be checked. If such variable is not set, default value will be used. Content in the yaml always beats the environment variable.

For instance, when user provides the following yaml

```yaml
log_filepath: my_own_log_file.txt
n_threads: 7
```

and sets `SECCERTS_MINIMAL_TOKEN_LENGTH=4` as environment variable, only these 3 keys will be loaded with `config.load_from_yaml()`, others will be untouched.

```{tip}
You can load settings even without providing yaml configuration. Simply set the corresponding environment variables or use `.env` file.
```

## Configuration keys, types, default values and descriptions


```{code-cell} python
from sec_certs.configuration import config, Configuration
from myst_nb import glue
from IPython.display import Markdown
import typing

type_hints = typing.get_type_hints(Configuration)
text = ""
for field, value in config.__fields__.items():
    text += f"`{field}`\n\n"
    text += f"- type: `{type_hints[field]}`\n"
    text += f"- default: `{value.default}`\n"
    text += f"- description: {value.field_info.description}\n"
    text += f"- env name: `{list(value.field_info.extra['env_names'])[0]}`\n\n"
glue("text", Markdown(text))
```
