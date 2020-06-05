#!/usr/bin/python
# -*- coding: utf-8 -*-
"""This is the setup file for the kordesii project."""
import sys
from setuptools import setup, find_packages


version_tuple = (sys.version_info[0], sys.version_info[1])

setup(
    name='kordesii',
    author='DC3',
    url='https://github.com/Defense-Cyber-Crime-Center/kordesii',
    keywords=['malware', 'ida', 'idapro'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    entry_points={
        'console_scripts': [
            'kordesii = kordesii.cli:main',
        ],
        'kordesii.decoders': [
            'kordesii = kordesii.decoders',
        ]
    },
    packages=find_packages(),
    include_package_data=True,
    license='MIT',
    python_requires='>=3.6',
    install_requires=[
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
    ],
    extras_require={
        'testing': [
            'pytest',
            'pytest-console-scripts',
            'nox',
        ]
    },
)
