from __future__ import absolute_import

from functools import partial

from txsni.snimap import SNIMap, HostDirectoryMap
from txsni.tlsendpoint import TLSEndpoint
from txsni.only_noticed_pypi_pem_after_i_wrote_this import objectsFromPEM
from txsni.parser import SNIDirectoryParser

from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from OpenSSL.SSL import Context, SSLv23_METHOD, Connection

from twisted.internet import protocol, endpoints, reactor, defer, interfaces
from twisted.internet.ssl import (
    CertificateOptions, optionsForClientTLS, Certificate
)
from twisted.python.filepath import FilePath
from twisted.trial import unittest

from zope.interface import implementer

from .certs.cert_builder import (
    ROOT_CERT_PATH, HTTP2BIN_CERT_PATH, CERT_DIR, _build_certs,
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


def handshake(
        client_factory,
        server_factory,
        hostname,
        server_endpoint,
        acceptable_protocols=None,
):
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

        maybe_alpn = {}
        if acceptable_protocols is not None:
            maybe_alpn['acceptableProtocols'] = acceptable_protocols

        options = optionsForClientTLS(
            hostname=hostname,
            trustRoot=PEM_ROOT,
            **maybe_alpn
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
        proto = self.transport.negotiatedProtocol

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
        self.transport.write(b'PING')
        self.transport.loseConnection()


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

def assert_cert_is(test_case, protocol_cert, cert_path):
    """
    Assert that ``protocol_cert`` is the same certificate as the one at
    ``cert_path``.
    """
    with open(cert_path, 'rb') as f:
        target_cert = load_certificate(FILETYPE_PEM, f.read())

    test_case.assertEqual(
        protocol_cert.digest('sha256'),
        target_cert.digest('sha256')
    )



class TestCommunication(unittest.TestCase):
    """
    Tests that use the full Twisted logic to validate that txsni works as
    expected.
    """

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
            assert_cert_is(self, cert, HTTP2BIN_CERT_PATH)
            return d

        def close(args):
            client, port = args
            port.stopListening()

        handshake_deferred.addCallback(confirm_cert)
        handshake_deferred.addCallback(close)
        return handshake_deferred


class TestPemObjects(unittest.TestCase, object):
    """
    Tests for L{objectsFromPEM}
    """

    def test_noObjects(self):
        """
        The empty string returns an empty list of certificates.
        """

        objects = objectsFromPEM(b"")
        self.assertEqual(objects.certificates, [])
        self.assertEqual(objects.keys, [])



def will_use_tls_1_3():
    """
    Will OpenSSL negotiate TLS 1.3?
    """
    ctx = Context(SSLv23_METHOD)
    connection = Connection(ctx, None)
    return connection.get_protocol_version_name() == u'TLSv1.3'


class TestNegotiationStillWorks(unittest.TestCase):
    """
    Tests that TxSNI doesn't break protocol negotiation.
    """

    EXPECTED_PROTOCOL = b'h2'

    def assert_specific_cert_still_negotiates(self, perform_handshake):
        """
        When TxSNI selects a specific cert, protocol negotiation still
        works.
        """
        handshake_deferred = defer.Deferred()
        client_factory = WritingNegotiatingFactory(handshake_deferred)
        server_factory = NegotiatingFactory.forProtocol(
            WriteBackProtocol
        )

        endpoint = sni_endpoint()
        d = perform_handshake(
            client_factory=client_factory,
            server_factory=server_factory,
            hostname=u'http2bin.org',
            server_endpoint=endpoint,
        )

        def confirm_cert(args):
            cert, proto = args
            self.assertEqual(proto, self.EXPECTED_PROTOCOL)
            return d

        def close(args):
            client, port = args
            port.stopListening()

        handshake_deferred.addCallback(confirm_cert)
        handshake_deferred.addCallback(close)
        return handshake_deferred


    def test_specific_cert_still_negotiates_with_alpn(self):
        """
        When TxSNI selects a specific cert, Application Level Protocol
        Negotiation (ALPN) still works.
        """
        return self.assert_specific_cert_still_negotiates(
            partial(handshake, acceptable_protocols=[self.EXPECTED_PROTOCOL])
        )


    def test_specific_cert_still_negotiates_with_npn(self):
        """
        When TxSNI selects a specific cert, Next Protocol Negotiation
        (NPN) still works.
        """
        return self.assert_specific_cert_still_negotiates(handshake)

    if will_use_tls_1_3():
        test_specific_cert_still_negotiates_with_npn.skip = (
            "OpenSSL does not support NPN with TLS 1.3"
        )


class TestSNIDirectoryParser(unittest.TestCase):
    """
    Tests the C{txsni} endpoint implementation.
    """

    def setUp(self):
        self.directory_parser = SNIDirectoryParser()

    def test_recreated_certificates(self):
        """
        L{SNIDirectoryParser} always uses the latest certificate for
        the requested domain.
        """
        endpoint = self.directory_parser.parseStreamServer(
                reactor, CERT_DIR, 'tcp', port='0', interface='127.0.0.1')

        def handshake_and_check(_):
            handshake_deferred = defer.Deferred()
            client_factory = WritingProtocolFactory(handshake_deferred)
            server_factory = protocol.Factory.forProtocol(WriteBackProtocol)

            initiate_handshake_deferred = handshake(
                    client_factory=client_factory,
                    server_factory=server_factory,
                    hostname=u"http2bin.org",
                    server_endpoint=endpoint,
                )

            def confirm_cert(args):
                cert, proto = args
                assert_cert_is(self, cert, HTTP2BIN_CERT_PATH)

            def close(args):
                client, port = args
                port.stopListening()

            exception = [None]

            def captureException(f):
                exception[0] = f

            def maybeRethrow(_):
                if exception[0] is not None:
                    exception[0].raiseException()

            handshake_deferred.addCallback(confirm_cert)
            handshake_deferred.addErrback(captureException)

            handshake_deferred.addCallback(lambda _: initiate_handshake_deferred)
            handshake_deferred.addCallback(close)

            handshake_deferred.addCallback(maybeRethrow)
            return handshake_deferred

        def reset_http2bin_cert(_):
            FilePath(HTTP2BIN_CERT_PATH).remove()
            _build_certs()

        old_cert_handshake = handshake_and_check(None)
        old_cert_handshake.addCallback(reset_http2bin_cert)
        return old_cert_handshake.addCallback(handshake_and_check)
