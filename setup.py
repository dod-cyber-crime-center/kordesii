#!/usr/bin/python
# -*- coding: utf-8 -*-
"""This is the setup file for the kordesii project."""
import os
import sys

from setuptools import setup, find_packages


version_tuple = (sys.version_info[0], sys.version_info[1])


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname), 'r') as fo:
        return fo.read()


setup(
    name='kordesii',
    version='1.7.0',
    author='DC3',
    description='A framework for decoding encoded strings and files in malware via IDA Pro IDAPython scripting.',
    url='https://github.com/Defense-Cyber-Crime-Center/kordesii',
    long_description=read('README.md'),
    keywords=['malware', 'ida', 'idapro'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [
            'kordesii = kordesii.cli:main',
            'kordesii-tool = kordesii.tools.tool:main',       # DEPRECATED
            'kordesii-client = kordesii.tools.client:main',   # DEPRECATED
            'kordesii-server = kordesii.tools.server:main',   # DEPRECATED
            'kordesii-test = kordesii.tools.test:main'        # DEPRECATED
        ],
        'kordesii.decoders': [
            'kordesii = kordesii.decoders',
        ]
    },
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.6',
    install_requires=[
        'bottle',
        'click',
        'dill',
        'numpy',
        'pyelftools',
        'pefile>=2019.4.18',
        'pycryptodome',
        'requests',
        'Pyro4',
        'pyyaml',
        'tabulate',
        'yara-python',
        'ruamel.yaml',
        'setuptools',
        'six',

        # For the server and API
        'flask~=1.1.0',
        'pygments~=2.2.0',

        # Testing
        'pytest',
        'pytest-console-scripts',
        'tox',
    ]
)
