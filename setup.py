#!/usr/bin/env python

from os import path
from setuptools import setup, find_packages

# Bump pfhb/__init__.py version as well.
__VERSION__ = '0.9.5'

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

description = ('Python package to dig hosts and generate PF (Packet Filter) '
               'rules')

setup_info = dict(
    name='pfhb',
    version=__VERSION__,
    author='Ricardo Falasca',
    author_email='ricardo@falasca.com.br',
    url='https://github.com/ricardofalasca/packet-filter-host-blocker/',
    description=description,
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(exclude=['tests*', 'scripts']),
    scripts=['scripts/pfhb-cli'],
    data_files=[
        ('/etc/pfhb', ['docs/settings.ini', 'docs/domains.ini']),
    ],
    include_package_data=True,
    license='MIT',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    zip_safe=True,
    install_requires=[
        'ipwhois==1.1.0',
        'redis==3.2.0',
    ]
)

setup(**setup_info)
