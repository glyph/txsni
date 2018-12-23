from __future__ import absolute_import

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from twisted.logger import Logger

import datetime
import uuid
import os
import tempfile


ONE_DAY = datetime.timedelta(1, 0, 0)
THIRTYISH_YEARS = datetime.timedelta(30 * 365, 0, 0)
TENISH_YEARS = datetime.timedelta(10 * 365, 0, 0)


# Various exportable constants that the tests can (and should!) use.
CERT_DIR = tempfile.mkdtemp()
ROOT_CERT_PATH = os.path.join(CERT_DIR, 'root_cert.pem')
ROOT_KEY_PATH = os.path.join(CERT_DIR, 'root_cert.key')
DEFAULT_CERT_PATH = os.path.join(CERT_DIR, 'DEFAULT.pem')
DEFAULT_KEY_PATH = os.path.join(CERT_DIR, 'DEFAULT.key')
HTTP2BIN_CERT_PATH = os.path.join(CERT_DIR, 'http2bin.org.pem')
HTTP2BIN_KEY_PATH = os.path.join(CERT_DIR, 'http2bin.org.key')


# A list of tuples that controls what certs get built and signed by the root.
# Each tuple is (hostname, cert_path)
# We'll probably never need the easy extensibility this provides, but hey, nvm!
_CERTS = [
    (u'localhost', DEFAULT_CERT_PATH),
    (u'http2bin.org', HTTP2BIN_CERT_PATH),
]


_LOGGER = Logger()

def _build_root_cert():
    """
    Builds a single root certificate that can be used to sign the others. This
    root cert is basically pretty legit, except for being totally bonkers.
    Returns a tuple of (certificate, key) for the CA, which can be used to
    build the leaves.
    """
    if os.path.isfile(ROOT_CERT_PATH) and os.path.isfile(ROOT_KEY_PATH):
        _LOGGER.info("Root already exists, not regenerating.")
        with open(ROOT_CERT_PATH, 'rb') as f:
            certificate = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )
        with open(ROOT_KEY_PATH, 'rb') as f:
            key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        return certificate, key

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'txsni signing service'),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'txsni signing service'),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
    builder = builder.not_valid_after(
        datetime.datetime.today() + THIRTYISH_YEARS
    )
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)

    # Don't allow intermediates.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Write it out.
    with open(ROOT_KEY_PATH, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(ROOT_CERT_PATH, 'wb') as f:
        f.write(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

    _LOGGER.info("Built root certificate.")

    return certificate, private_key


def _build_single_leaf(hostname, certfile, ca_cert, ca_key):
    """
    Builds a single leaf certificate, signed by the CA's private key.
    """
    if os.path.isfile(certfile):
        _LOGGER.info("{hostname} already exists, not regenerating",
                     hostname=hostname)
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ]))
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.today() - ONE_DAY)
    builder = builder.not_valid_after(
        datetime.datetime.today() + TENISH_YEARS
    )
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(hostname)
        ]),
        critical=True,
    )

    certificate = builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Write it out.
    with open(certfile, 'wb') as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        f.write(
            certificate.public_bytes(serialization.Encoding.PEM)
        )

    _LOGGER.info("Built certificate for {hostname}", hostname=hostname)


def _build_certs():
    """
    Builds all certificates.
    """
    ca_cert, ca_key = _build_root_cert()

    for hostname, certfile in _CERTS:
        _build_single_leaf(hostname, certfile, ca_cert, ca_key)


if __name__ == '__main__':
    _build_certs()
