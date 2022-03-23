#!/usr/bin/python
# -*- coding: utf-8 -*-
"""This is the setup file for the kordesii project."""
import sys
from setuptools import setup, find_packages


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
        'dill',  # DEPRECATED
        'numpy',
        'pyelftools',
        'pefile>=2019.4.18',
        'pycryptodome',
        'requests',
        'Pyro4',  # DEPRECATED
        'pyyaml',
        'tabulate',
        'yara-python',
        # Forcing newer version ruamel.yaml to keep serialization consistent among Windows and Linux.
        'ruamel.yaml>=0.16.12',
        'setuptools',
        'six',

        # For the server and API
        'flask',
        'pygments',
    ],
    extras_require={
        'testing': [
            'pytest>=3.0.0',
            'pytest-console-scripts',
        ]
    },
)
