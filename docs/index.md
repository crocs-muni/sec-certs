# Sec-certs documentation

Welcome to the technical documentation of *sec-certs* tool for the data analysis of products certified with Common Criteria or FIPS 140 frameworks. If you're looking for general description of the tool, its use cases and capabilites, we refer you to [sec-certs homepage](https://sec-certs.org/). If you are looking for more advanced knowledge, e.g. how to mine your own data, how to extend the tool, and so forth, this is the right place.

There are three main parts of this documentation. *Quickstart* describes high-level use of our tool. Driven by this knowledge, you can progress to *Notebook examples* that showcase some of the API that we use in the form of Jupyter notebooks. The documentation also contains some of the modules documented with `autodoc`, see *API reference*. Still, some dark corners of our codebase are not documented. To inspect the code directly, see the [sec_certs](https://github.com/crocs-muni/sec-certs/tree/main/src/sec_certs) module. If you want, you can run the notebooks as they are stored in the [project repository](https://github.com/crocs-muni/sec-certs/tree/main/notebooks). If you are interested in contributing to our project or in other aspects of our development, you can consult the relevant *GitHub artifacts*.

```{button-ref} quickstart
:align: center
:color: primary
:ref-type: myst
Show me Quickstart!
```

```{admonition} Launch notebooks in MyBinder
Each of the notebooks can be launched interactively in MyBinder by clicking on 🚀 icon (top-right corner).
```

```{toctree}
:hidden:
:caption: Navigation
:maxdepth: 1
Sec-certs homepage <https://sec-certs.org/>
Sec-certs docs <https://sec-certs.org/docs>
GitHub repo <https://github.com/crocs-muni/sec-certs>
```

```{toctree}
:hidden: True
:caption: User's guide
:maxdepth: 1
installation.md
quickstart.md
configuration.md
user_guide.md
search_examples.md
```

```{toctree}
:caption: Notebook examples
:hidden: True
:maxdepth: 1
Demo <notebooks/examples/est_solution.ipynb>
Common Criteria <notebooks/examples/cc.ipynb>
Protection Profiles <notebooks/examples/protection_profiles.ipynb>
FIPS-140 <notebooks/examples/fips.ipynb>
FIPS-140 IUT <notebooks/examples/fips_iut.ipynb>
FIPS-140 MIP <notebooks/examples/fips_mip.ipynb>
Model <notebooks/examples/model.ipynb>
```

```{toctree}
:caption: API reference
:hidden: True
:maxdepth: 1
api/sample.md
api/dataset.md
api/model.md
```

```{toctree}
:maxdepth: 1
:hidden: True
:caption: GitHub artifacts
README <readme.md>
contributing.md
code_of_conduct.md
license.md
```
