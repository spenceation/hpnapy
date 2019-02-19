# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from os import path

import sys

if sys.version_info < (3, 4):
    sys.exit('hpnapy requires Python 3.4+')

VERSION = '1.0.5'

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    readme_text = f.read()

with open(path.join(here, 'LICENSE'), encoding='utf-8') as f:
    license_text = f.read()

setup(
    name='hpnapy',
    version=VERSION,
    description='HP Network automation framework',
    long_description=readme_text,
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Network Engineers',
        'License :: OSI Approved :: GNU GPLv3',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries',
        'Topic :: Network Automation',
    ],
    author='Spencer Ervin',
    author_email='spenceation@hotmail.com',
    url='https://github.com/spenceation/hpnapy',
    license=license_text,
    install_requires=['requests>=1.0.0',
                      'zeep>=3.0.0',
                      'urllib3>=1.0.0'],
    packages=find_packages(exclude=('tests', 'docs'))
)
