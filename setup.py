#!/usr/bin/env python3
# coding: utf-8
import os
from setuptools import setup

setup(
    name = "pinecone",
    version = "0.2.1",
    author = u"Pinecrypt Labs",
    author_email = "info@pinecrypt.com",
    description = "Pinecrypt Gateway",
    license = "MIT",
    keywords = "falcon http jinja2 x509 pkcs11 webcrypto kerberos ldap",
    url = "http://github.com/laurivosandi/certidude",
    packages=[
        "pinecrypt.server",
        "pinecrypt.server.api",
        "pinecrypt.server.api.utils"
    ],
    long_description=open("README.md").read(),
    # Include here only stuff required to run certidude client
    install_requires=[
        "asn1crypto",
        "click",
        "configparser",
        "certbuilder",
        "csrbuilder",
        "crlbuilder",
        "jinja2",
    ],
    scripts=[
        "misc/pinecone"
    ],
    include_package_data = True,
    package_data={
        "pinecrypt": ["pinecrypt/server/templates/*", "pinecrypt/server/builder/*"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: Freely Distributable",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
    ],
)

