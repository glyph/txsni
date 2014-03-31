
from OpenSSL.SSL import FILETYPE_PEM

from twisted.internet.ssl import Certificate, KeyPair, CertificateOptions
from collections import namedtuple

PEMObjects = namedtuple('PEMObjects', ['certificates', 'keys'])

def objectsFromPEM(pemdata):
    """
    Load some objects from a PEM.
    """
    certificates = []
    keys = []
    for line in pemdata.split("\n"):
        if line.startswith('-----BEGIN'):
            if 'CERTIFICATE' in line:
                blobs = certificates
            else:
                blobs = keys
            blobs.append('')
        blobs[-1] += line
        blobs[-1] += '\n'
    keys = [KeyPair.load(key, FILETYPE_PEM) for key in keys]
    certificates = [Certificate.loadPEM(certificate)
                    for certificate in certificates]
    return PEMObjects(keys=keys, certificates=certificates)



def certificateOptionsFromPileOfPEM(pemdata):
    objects = objectsFromPEM(pemdata)
    if len(objects.keys) != 1:
        raise ValueError("Expected 1 private key, found %d"
                         % tuple([len(objects.keys)]))

    privateKey = objects.keys[0]

    certificatesByFingerprint = dict(
        [(certificate.getPublicKey().keyHash(), certificate)
         for certificate in objects.certificates]
    )

    if privateKey.keyHash() not in certificatesByFingerprint:
        raise ValueError("No certificate matching %s found")

    openSSLCert = certificatesByFingerprint.pop(privateKey.keyHash()).original
    openSSLKey = privateKey.original
    openSSLChain = [c.original for c in certificatesByFingerprint.values()]

    return CertificateOptions(certificate=openSSLCert, privateKey=openSSLKey,
                              extraCertChain=openSSLChain)
