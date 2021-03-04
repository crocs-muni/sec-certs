#!/usr/bin/env python3
from setuptools import setup, find_packages

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='sec-certs',
    author='Petr Svenda, Stanislav Bobon, Jan Jancar, Adam Janovsky',
    author_email='svenda@fi.muni.cz',
    version='0.0.0',
    packages=find_packages(),
    license='MIT',
    description="Tool for analysis of security certificates",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research"
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": ["mypy", "flake8"],
        "test": ["pytest", "coverage"]
    },
    entry_points="""
        [console_scripts]
        process-certs=process_certificates:main
        fips-certs=fips_certificates:main
    """
)
