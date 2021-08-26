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
    version='1.8.1',
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
    python_requires='>=3.4',
    entry_points={
        "console_scripts": [
            "pocsuite = pocsuite3.cli:main",
            "poc-console = pocsuite3.console:main"
        ]
    },
    install_requires=[
        "requests >= 2.22.0",
        "PySocks >= 1.7.1",
        "requests-toolbelt >= 0.9.1",
        "urllib3 >= 1.25.6",
        "setuptools >= 51.1.2",
        "chardet >= 3.0.4",
        "termcolor >= 1.1.0",
        "colorama >= 0.4.4",
        "prettytable >= 0.7.2",
        "colorlog >= 4.7.2",
        "scapy >= 2.4.4",
        "pyOpenSSL >= 20.0.0"
    ],
)
