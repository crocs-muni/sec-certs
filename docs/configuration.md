---
file_format: mystnb
mystnb:
  remove_code_source: true
  execution_mode: 'force'
---
# Configuration

The configuration is stored in yaml file `settings.yaml` at `sec_certs.config` package. Below are the supported options, descriptions and default values.


```{code-cell} python
from sec_certs.config import configuration
from myst_nb import glue
from IPython.display import Markdown

cfg = configuration.config
text = ""
for key in cfg.__dict__:
    text += f"`{key}`\n\n- Description: {cfg.get_desription(key)}\n"
    text += f"- Default value: `{cfg.__getattribute__(key)}`\n\n"
glue("text", Markdown(text))
```
```{glue:md} text
:format: myst
```
