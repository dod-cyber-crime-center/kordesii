#!/usr/bin/python
# -*- coding: utf-8 -*-
"""This is the setup file for the kordesii project."""
import os
import sys

from setuptools import setup, find_packages


version_tuple = (sys.version_info[0], sys.version_info[1])
if version_tuple < (2, 7) or version_tuple >= (3, 0):
    print(('Unsupported Python version: {0:s}, version 2.7 or higher and '
         'lower than 3.x required.').format(sys.version))
    sys.exit(1)


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname), 'r') as fo:
        return fo.read()


setup(
    name='kordesii',
    version='1.4.1',
    author='DC3',
    description='A framework for decoding encoded strings and files in malware via IDA Pro IDAPython scripting.',
    url='https://github.com/Defense-Cyber-Crime-Center/kordesii',
    long_description=read('README.md'),
    keywords=['malware', 'ida', 'idapro'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    entry_points={
        'console_scripts': [
            'kordesii = kordesii.cli:main',
            'kordesii-tool = kordesii.tools.kordesii_tool:main',
            'kordesii-client = kordesii.tools.kordesii_client:main',
            'kordesii-server = kordesii.tools.kordesii_server:main',
            'kordesii-test = kordesii.tools.kordesii_test:main'
        ],
        'kordesii.decoders': [
            'kordesii = kordesii.decoders',
        ]
    },
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=2.7, <3',
    install_requires=[
        'bottle',
        'click',
        'numpy',
        'pyelftools',
        'pefile',
        'PyCrypto',
        'requests',
        'pyyaml',
        'tabulate',
        'yara-python',
        'ruamel.yaml',
        'six',

        # Testing
        'pytest',
        'pytest-console-scripts',
        'tox',
    ]
)
