#!/usr/bin/env python
import os
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

    def find_packages(where='.'):
        # os.walk -> list[(dirname, list[subdirs], list[files])]
        return [folder.replace(os.sep, ".").strip(".")
                for (folder, _, files) in os.walk(where)
                if "__init__.py" in files]


setup(
    name='pocsuite3',
    version='1.8.3',
    url='http://pocsuite.org',
    description='Pocsuite is an open-sourced remote vulnerability testing framework developed by the Knownsec Security Team.',
    long_description="""\
Pocsuite is an open-sourced remote vulnerability testing and proof-of-concept development framework developed by the Knownsec Security Team. It comes with a powerful proof-of-concept engine, many niche features for the ultimate penetration testers and security researchers.""",
    keywords='PoC,Exp,Pocsuite',
    author='Knownsec Security Team',
    author_email='s1@seebug.org',
    maintainer='pocsuite developers',
    platforms=['any'],
    license='GPL 2.0',
    zip_safe=False,
    packages=find_packages(),
    include_package_data=True,
    python_requires='>=3.6',
    entry_points={
        "console_scripts": [
            "pocsuite = pocsuite3.cli:main",
            "poc-console = pocsuite3.console:main"
        ]
    },
    install_requires=[
        "requests",
        "requests-toolbelt",
        "PySocks",
        "urllib3",
        "chardet",
        "termcolor",
        "colorama",
        "prettytable",
        "colorlog",
        "scapy"
    ],
    extras_require={
        'complete': [
            'pyOpenSSL'
        ],
    }
)
