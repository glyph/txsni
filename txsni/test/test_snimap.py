from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from twisted.internet.ssl import Certificate, KeyPair, PrivateCertificate
from twisted.python.filepath import FilePath
from twisted.trial.unittest import SynchronousTestCase

from txsni.snimap import HostDirectoryMap



def _makeCertificateFor(hostname, signingKey=None, issuer=None):
    """
    Make a new certificate valid for the given hostname.
    """
    privateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    if signingKey is None:
        signingKey = privateKey
    publicKey = privateKey.public_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    if issuer is None:
        issuer = name
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .not_valid_before(datetime.today() - timedelta(days=1))
        .not_valid_after(datetime.today() + timedelta(days=1))
        .serial_number(1)
        .public_key(publicKey)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname)]),
            critical=False)
        .sign(
            private_key=signingKey,
            algorithm=hashes.SHA256(),
            backend=default_backend()))
    return privateKey, certificate


def _serializeCertificate(privateKey, certificate):
    """
    Serialize a L{cryptography} private key and certificate as PKCS 8 / PEM.
    """
    return '\n'.join([
        privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()),
        certificate.public_bytes(
            encoding=serialization.Encoding.PEM),
        ])


def _optionsFromCertificate(privateKey, certificate):
    """
    Convert a L{cryptography} private key and certificate to
    L{PrivateCertificate}.
    """
    # This is kinda silly but there's no particularly good way to do this
    # conversion otherwise.
    return PrivateCertificate.loadPEM(
        _serializeCertificate(privateKey, certificate)).options()



class HostDirectoryMapTests(SynchronousTestCase):
    """
    L{HostDirectoryMap} maps hostnames to certificate options loaded from a
    directory.
    """
    def setUp(self):
        self.certsDir = FilePath(self.mktemp())
        self.certsDir.makedirs()
        self.mapping = HostDirectoryMap(self.certsDir)


    def test_certificateMissing(self):
        """
        If a certificate for a given hostname does not exist, C{__getitem__}
        raises L{KeyError}.
        """
        self.assertRaises(KeyError, lambda: self.mapping['example.com'])
        self.assertIdentical(self.mapping.get('example.com', None), None)


    def test_getCertificate(self):
        """
        If a certificate for a given hostname exists, C{__getitem__} constructs
        L{twisted.internet.ssl.CertificateOptions} out of the certificate,
        private key, and any chain certificates that may be present.
        """
        key1, cert1 = _makeCertificateFor(u'example.com')
        chainCert1 = _makeCertificateFor(u'example.org')[1]
        self.certsDir.child('example.com.pem').setContent(
            _serializeCertificate(key1, cert1) + '\n' +
            chainCert1.public_bytes(encoding=serialization.Encoding.PEM))
        options = self.mapping['example.com']
        key2 = options.privateKey
        cert2 = options.certificate
        self.assertEqual(
            cert1.fingerprint(hashes.SHA256()),
            cert2.digest('sha256').replace(':', '').decode('hex'))
        # Ugh, too hard to actually compare the keys. This case is covered
        # indirectly by C{test_setAndGet} anyway.
        self.assertNotIdentical(key2, None)
        self.assertEqual(len(options.extraCertChain), 1)
        chainCert2 = options.extraCertChain[0]
        self.assertEqual(
            chainCert1.fingerprint(hashes.SHA256()),
            chainCert2.digest('sha256').replace(':', '').decode('hex'))


    def test_setAndGet(self):
        """
        L{HostDirectoryMap.__setitem__} serializes a certificate to disk,
        L{HostDirectoryMap.__getitem__} gets it back
        """
        options1 = _optionsFromCertificate(
            *_makeCertificateFor(u'example.com'))
        key1 = KeyPair(options1.privateKey)
        cert1 = Certificate(options1.certificate)
        self.assertFalse(self.certsDir.child('example.com.pem').exists())
        self.mapping['example.com'] = options1
        self.assertTrue(self.certsDir.child('example.com.pem').exists())
        options2 = self.mapping['example.com']
        key2 = KeyPair(options2.privateKey)
        cert2 = Certificate(options2.certificate)
        # This is kinda terrible, but Twisted lacks better APIs for this
        self.assertEqual(key1.original.type(), key2.original.type())
        self.assertEqual(key1.keyHash(), key2.keyHash())
        self.assertEqual(cert1.digest('sha256'), cert2.digest('sha256'))


    def test_delete(self):
        """
        L{HostDirectoryMap.__delitem__} deletes the corresponding certificate
        from disk.
        """
        certPath = self.certsDir.child('example.com.pem')
        certPath.touch()
        self.assertIn('example.com', self.mapping)
        self.assertTrue(certPath.exists())
        del self.mapping['example.com']
        certPath.changed()
        self.assertNotIn('example.com', self.mapping)
        self.assertFalse(certPath.exists())


    def test_deleteKeyError(self):
        """
        L{HostDirectoryMap.__delitem__} raises L{KeyError} if the certificate
        does not exist.
        """
        def _del():
            del self.mapping['example.com']
        self.assertRaises(KeyError, _del)


    def test_len(self):
        """
        L{HostDirectoryMap.__len__} returns the number of certificates in the
        directory.
        """
        self.assertEqual(len(self.mapping), 0)
        self.certsDir.child('example.com.pem').touch()
        self.assertEqual(len(self.mapping), 1)
        self.certsDir.child('example.org.pem').touch()
        self.assertEqual(len(self.mapping), 2)


    def test_iter(self):
        """
        L{HostDirectoryMap.__iter__} returns an iterator over the hostnames of
        the certificates in the directory.
        """
        self.assertEqual(list(self.mapping), [])
        self.certsDir.child('example.com.pem').touch()
        self.assertEqual(list(self.mapping), ['example.com'])
        self.certsDir.child('example.org.pem').touch()
        self.assertEqual(list(self.mapping), ['example.com', 'example.org'])
