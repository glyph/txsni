
from setuptools import setup

setup(
    name = "TxSNI",
    description = "easy-to-use SNI endpoint for twisted",
    packages = [
        "txsni",
        "twisted.plugins",
    ],
    install_requires = [
        "Twisted>=13.2",
        "pyOpenSSL>=0.14",
    ],
    version = "0.1",
)
