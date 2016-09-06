from __future__ import absolute_import

import os

from txsni.snimap import SNIMap, HostDirectoryMap
from txsni.tlsendpoint import TLSEndpoint

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from twisted.internet import protocol, endpoints, reactor, defer, interfaces
from twisted.internet.ssl import (
    CertificateOptions, optionsForClientTLS, Certificate
)
from twisted.python.filepath import FilePath
from twisted.trial import unittest

from zope.interface import implementer

from .certs.cert_builder import (
    ROOT_CERT_PATH, HTTP2BIN_CERT_PATH, _build_certs, CERT_DIR
)

# We need some temporary certs.
_build_certs()

with open(ROOT_CERT_PATH, 'rb') as f:
    PEM_ROOT = Certificate.loadPEM(f.read())


def sni_endpoint():
    """
    Builds a TxSNI TLSEndpoint populated with the default certificates. These
    are built from cert_builder.py, and have the following certs in the SNI
    map:

    - DEFAULT.pem, which contains a SAN for 'localhost'.
    - http2bin.org.pem, which contains a SAN for 'http2bin.org'
    """
    base_endpoint = endpoints.TCP4ServerEndpoint(
        reactor=reactor,
        port=0,
        interface='127.0.0.1',
    )
    path = FilePath(CERT_DIR)
    mapping = SNIMap(HostDirectoryMap(path))
    wrapper_endpoint = TLSEndpoint(base_endpoint, mapping)
    return wrapper_endpoint


def handshake(client_factory, server_factory, hostname, server_endpoint):
    """
    Connect a basic Twisted TLS client endpoint to the provided TxSNI
    TLSEndpoint. Returns a Deferred that fires when the connection has been
    established with a tuple of an instance of the client protocol and the
    listening port.
    """
    def connect_client(listening_port):
        port_number = listening_port.getHost().port

        client = endpoints.TCP4ClientEndpoint(
            reactor, '127.0.0.1', port_number
        )
        options = optionsForClientTLS(
            hostname=hostname, trustRoot=PEM_ROOT
        )
        client = endpoints.wrapClientTLS(options, client)
        connectDeferred = client.connect(client_factory)

        def aggregate(client_proto):
            return (client_proto, listening_port)

        connectDeferred.addCallback(aggregate)
        return connectDeferred

    listenDeferred = server_endpoint.listen(server_factory)
    listenDeferred.addCallback(connect_client)
    return listenDeferred


class WritingProtocol(protocol.Protocol):
    """
    A really basic Twisted protocol that fires a Deferred when the TLS
    handshake has been completed. It detects this using dataReceived, because
    we can't rely on IHandshakeListener.
    """
    def __init__(self, handshake_deferred):
        self.handshake_deferred = handshake_deferred

    def dataReceived(self, data):
        cert = self.transport.getPeerCertificate()

        if not skipNegotiation:
            proto = self.transport.negotiatedProtocol
        else:
            proto = None
        self.transport.abortConnection()
        self.handshake_deferred.callback((cert, proto))
        self.handshake_deferred = None


class WritingProtocolFactory(protocol.Factory):
    protocol = WritingProtocol

    def __init__(self, handshake_deferred):
        self.handshake_deferred = handshake_deferred

    def buildProtocol(self, addr):
        p = self.protocol(self.handshake_deferred)
        p.factory = self
        return p


class WriteBackProtocol(protocol.Protocol):
    """
    A really basic Twisted protocol that just writes some data to the
    connection.
    """
    def connectionMade(self):
        self.transport.write('PING')
        self.transport.loseConnection()


try:
    @implementer(interfaces.IProtocolNegotiationFactory)
    class NegotiatingFactory(protocol.Factory):
        """
        A Twisted Protocol Factory that implements the protocol negotiation
        extensions
        """
        def acceptableProtocols(self):
            return [b'h2', b'http/1.1']

    class WritingNegotiatingFactory(WritingProtocolFactory,
                                    NegotiatingFactory):
        pass

    skipNegotiation = False
except AttributeError:
    skipNegotiation = "IProtocolNegotiationFactory not supported"


class TestSNIMap(unittest.TestCase):
    """
    Tests of the basic SNIMap logic.
    """
    def test_snimap_default(self):
        """
        SNIMap preferentially loads the DEFAULT value from the mapping if it's
        present.
        """
        options = CertificateOptions()
        mapping = {'DEFAULT': options}
        sni_map = SNIMap(mapping)

        conn = sni_map.serverConnectionForTLS(protocol.Protocol())
        self.assertIs(conn.get_context()._obj, options.getContext())

    def test_snimap_makes_its_own_defaults(self):
        """
        If passed a mapping without a DEFAULT key, SNIMap will make its own
        default context.
        """
        options = CertificateOptions()
        mapping = {'example.com': options}
        sni_map = SNIMap(mapping)

        conn = sni_map.serverConnectionForTLS(protocol.Protocol())
        self.assertIsNot(conn.get_context(), options.getContext())
        self.assertIsNotNone(conn.get_context())


class TestCommunication(unittest.TestCase):
    """
    Tests that use the full Twisted logic to validate that txsni works as
    expected.
    """
    def assertCertIs(self, protocol_cert, cert_path):
        """
        Assert that ``protocol_cert`` is the same certificate as the one at
        ``cert_path``.
        """
        with open(cert_path, 'rb') as f:
            target_cert = load_certificate(FILETYPE_PEM, f.read())

        self.assertEqual(
            protocol_cert.digest('sha256'),
            target_cert.digest('sha256')
        )

    def test_specific_certificate(self):
        """
        When a hostname TxSNI does know about, in this case 'http2bin.org', is
        provided, TxSNI returns the specific certificate.
        """
        handshake_deferred = defer.Deferred()
        client_factory = WritingProtocolFactory(handshake_deferred)
        server_factory = protocol.Factory.forProtocol(WriteBackProtocol)

        endpoint = sni_endpoint()
        d = handshake(
            client_factory=client_factory,
            server_factory=server_factory,
            hostname=u'http2bin.org',
            server_endpoint=endpoint,
        )

        def confirm_cert(args):
            cert, proto = args
            self.assertCertIs(cert, HTTP2BIN_CERT_PATH)
            return d

        def close(args):
            client, port = args
            port.stopListening()

        handshake_deferred.addCallback(confirm_cert)
        handshake_deferred.addCallback(close)
        return handshake_deferred


class TestNegotiationStillWorks(unittest.TestCase):
    """
    Tests that TxSNI doesn't break protocol negotiation.
    """
    if skipNegotiation:
        skip = skipNegotiation

    def test_specific_cert_still_negotiates(self):
        """
        When TxSNI selects a specific cert, protocol negotiation still works.
        """
        handshake_deferred = defer.Deferred()
        client_factory = WritingNegotiatingFactory(handshake_deferred)
        server_factory = NegotiatingFactory.forProtocol(
            WriteBackProtocol
        )

        endpoint = sni_endpoint()
        d = handshake(
            client_factory=client_factory,
            server_factory=server_factory,
            hostname=u'http2bin.org',
            server_endpoint=endpoint,
        )

        def confirm_cert(args):
            cert, proto = args
            self.assertEqual(proto, b'h2')
            return d

        def close(args):
            client, port = args
            port.stopListening()

        handshake_deferred.addCallback(confirm_cert)
        handshake_deferred.addCallback(close)
        return handshake_deferred
