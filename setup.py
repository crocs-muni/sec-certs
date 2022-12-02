#!/usr/bin/env python3
from setuptools import find_packages, setup

setup(
    name="sec-certs",
    author="Petr Svenda, Stanislav Bobon, Jan Jancar, Adam Janovsky, Jiri Michalik",
    author_email="svenda@fi.muni.cz",
    packages=find_packages(),
    license="MIT",
    description="Tool for analysis of security certificates",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
    ],
    python_requires=">=3.8",
    install_requires=open("requirements/requirements.in").read().splitlines(),
    extras_require={
        "dev": open("requirements/dev_requirements.in").read().splitlines(),
        "test": open("requirements/test_requirements.in").read().splitlines(),
    },
    include_package_data=True,
    package_data={"sec_certs": ["settings.yaml", "settings-schema.json", "rules.yaml"]},
    entry_points={"console_scripts": ["sec-certs=sec_certs.cli:main"]},
    project_urls={
        "Project homepage": "https://seccerts.org",
        "GitHub repository": "https://github.com/crocs-muni/sec-certs/",
        "Documentation": "https://seccerts.org/docs",
    },
)
