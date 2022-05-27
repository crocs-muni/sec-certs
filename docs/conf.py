# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath("."))
from importlib.metadata import version as get_version

# -- Project information -----------------------------------------------------

project = "sec-certs"
copyright = "2020-2022, Adam Janovsky, Petr Svenda, Jan Jancar, Jiri Michalik, Stanislav Bobon."
# author = "Adam Janovsky, Petr Svenda, Jan Jancar, Jiri Michalik, Stanislav Bobon"

# Note thas this inference won't work from Docker: https://github.com/pypa/setuptools_scm/#usage-from-docker
release = ".".join(get_version("sec-certs").split(".")[:3])

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ["myst_nb", "sphinx.ext.autodoc", "sphinx_design", "sphinx_copybutton"]

# Don't exeute notbooks
nb_execution_mode = "off"

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# Don't show typehints in autodoc files
autodoc_typehints = "none"

# This is recommended by sphinx_design extension
myst_enable_extensions = ["colon_fence"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_book_theme"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

html_logo = "_static/logo.svg"
html_favicon = "_static/logo_badge.svg"

html_theme_options = {
    "repository_url": "https://github.com/crocs-muni/sec-certs",
    "repository_branch": "main",
    "launch_buttons": {"binderhub_url": "https://mybinder.org"},
    "use_fullscreen_button": False,
}

myst_heading_anchors = 3
