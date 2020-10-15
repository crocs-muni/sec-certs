#!/usr/bin/env python3
from setuptools import setup

setup(
    name='sec-certs',
    author='Petr Svenda',
    author_email='',
    version='0.0.0',
    packages='sec-certs',
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
    install_requires=[
        "PyPDF2",
        "matplotlib",
        "graphviz",
        "numpy",
        "tabulate"
    ]
)
