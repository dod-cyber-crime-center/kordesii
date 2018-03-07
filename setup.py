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
    version='1.0',
    author='DC3',
    description='A framework for decoding encoded strings and files in malware via IDA Pro IDAPython scripting.',
    long_description=read('README.md'),
    entry_points={
        'console_scripts': [
            'kordesii = kordesii.tools.kordesii_tool:main',
            'kordesii-client = kordesii.tools.kordesii_client:main',
            'kordesii-server = kordesii.tools.kordesii_server:main',
            'kordesii-test = kordesii.tools.kordesii_test:main'
        ]},
    packages=find_packages(),
    package_dir={
        'kordesii': 'kordesii',
    },
    include_package_data=True,
    install_requires=[
        'bottle',
        'pyelftools',
        'pefile',
        'requests',
        'yara-python'
    ]
)
