import os
try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup

    def find_packages(where='.'):
        # os.walk -> list[(dirname, list[subdirs], list[files])]
        return [folder.replace("/", ".").lstrip(".")
                for (folder, _, fils) in os.walk(where)
                if "__init__.py" in fils]

from pocsuite3 import __version__, __author__, __author_email__, __license__


setup(
    name='pocsuite3',
    version=__version__,
    url='http://pocsuite.org',
    description='Pocsuite is an open-sourced remote vulnerability testing framework developed by the Knownsec Security Team.',
    long_description="""\
Pocsuite is an open-sourced remote vulnerability testing and proof-of-concept development framework developed by the Knownsec Security Team. It comes with a powerful proof-of-concept engine, many niche features for the ultimate penetration testers and security researchers.""",
    keywords='PoC,Exp,Pocsuite',
    author=__author__,
    author_email=__author_email__,
    maintainer='pocsuite developers',
    platforms=['any'],
    license=__license__,
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
        'requests',
        'requests-toolbelt',
    ],
)
