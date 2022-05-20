# Sec-certs documentation

Welcome to the technical documentation of *sec-certs* tool for the data analysis of products certified with Common Criteria or FIPS 140 frameworks. If you're looking for general description of the tool, its use cases and capabilites, we refer you to [sec-certs homepage](https://seccerts.org/). If you are looking for more advanced knowledge, e.g. how to mine your own data, how to extend the tool, and so forth, this is the right place.

There are three main parts of this documentation. *User's guide* describes high-level use of our tool. Driven by this knowledge, you can progress to *Notebook examples* that showcase most of the API that we use in the form of Jupyter notebooks. The documentation currently does not have all modules documented with `autodoc`, so for the API reference, you must directly inspect the [sec_certs](https://github.com/crocs-muni/sec-certs/tree/main/sec_certs) module. If you want, you can run the notebooks as they are stored in the [project repository](https://github.com/crocs-muni/sec-certs/tree/main/notebooks). If you are interested in contributing to our project or in other aspects of our development, you can consult the relevant *GitHub artifacts*

```{admonition} Launch notebooks in MyBinder
Each of the notebooks can be launched interactively in MyBinder by clicking on 🚀 icon (top-right corner).
```

```{toctree}
:hidden:
:caption: Navigation
Seccerts homepage <https://seccerts.org/>
Seccerts docs <https://seccerts.org/docs>
GitHub repo <https://github.com/crocs-muni/sec-certs>
Seccerts PyPi <https://pypi.org/project/sec-certs/>
```

```{toctree}
:caption: User's guide
installation.md
quickstart.md
tutorial.md
```

```{toctree}
:caption: Notebook examples
notebooks/examples/common_criteria.ipynb
notebooks/examples/fips.ipynb
notebooks/examples/model.ipynb
```

```{toctree}
:caption: API
api/model.md
```

```{toctree}
:maxdepth: 2
:caption: GitHub artifacts
readme.md
contributing.md
code_of_conduct.md
license.md
```