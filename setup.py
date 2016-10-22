
import os

from setuptools import setup

base_dir = os.path.dirname(__file__)

with open(os.path.join(base_dir, "README.rst")) as f:
    long_description = f.read()

setup(
    name="TxSNI",
    description="easy-to-use SNI endpoint for twisted",
    packages=[
        "txsni",
        "txsni.test",
        "txsni.test.certs",
        "twisted.plugins",
    ],
    install_requires=[
        "Twisted[tls]>=14.0",
        "pyOpenSSL>=0.14",
    ],
    version="0.1.7",
    long_description=long_description,
    license="MIT",
    url="https://github.com/glyph/txsni",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security :: Cryptography",
    ],
)
