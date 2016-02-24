# -*- test-case-name: txsni.test.test_snimap -*-
from collections import MutableMapping

from OpenSSL.crypto import FILETYPE_PEM
from twisted.internet.ssl import (
    Certificate, CertificateOptions, ContextFactory, KeyPair)

from txsni.only_noticed_pypi_pem_after_i_wrote_this import (
    certificateOptionsFromPileOfPEM
)


class SNIMap(ContextFactory, object):
    """
    A context factory that switches contexts based on SNI.

    @type mapping: L{collections.Mapping}
    @ivar mapping: A mapping from hostnames to certificate options.
    """
    def __init__(self, mapping):
        self.mapping = mapping
        try:
            self.context = self.mapping[None].getContext()
        except KeyError:
            self.context = CertificateOptions().getContext()
        self.context.set_tlsext_servername_callback(
            self.selectContext
        )

    def getContext(self):
        return self.context

    def selectContext(self, connection):
        connection.set_context(
            self.mapping[connection.get_servername()]
            .getContext()
        )



class HostDirectoryMap(MutableMapping):
    def __init__(self, directoryPath):
        self.directoryPath = directoryPath


    def _listHosts(self):
        """
        Construct an iterator over all hostnames for which certificates are
        present.
        """
        return (
            name.split('.pem', 1)[0]
            for name in self.directoryPath.listdir()
            if name.endswith('.pem'))


    def _certPath(self, hostname):
        """
        Get the path for the certificate for a particular hostname.

        The special case of C{None} is mapped to the hostname C{'DEFAULT'}.

        @type hostname: L{str}
        @param hostname: The hostname.

        @rtype: L{twisted.python.filepath.FilePath}
        @return: A FilePath to the file with certificate data.
        """
        if hostname is None:
            hostname = 'DEFAULT'
        return self.directoryPath.child(hostname + '.pem')


    def __getitem__(self, hostname):
        filePath = self._certPath(hostname)
        if filePath.isfile():
            return certificateOptionsFromPileOfPEM(filePath.getContent())
        else:
            raise KeyError("no pem file for " + hostname)


    def __setitem__(self, hostname, options):
        filePath = self._certPath(hostname)
        pem = '\n'.join([
            KeyPair(options.privateKey).dump(FILETYPE_PEM),
            Certificate(options.certificate).dumpPEM(),
            ] + [Certificate(c).dumpPEM() for c in options.extraCertChain])
        filePath.setContent(pem)


    def __delitem__(self, hostname):
        filePath = self._certPath(hostname)
        if not filePath.isfile():
            # This is silly, but the mapping interface specifies it.
            raise KeyError(hostname)
        filePath.remove()


    def __len__(self):
        return sum(1 for _ in self._listHosts())


    def __iter__(self):
        return self._listHosts()


    def __contains__(self, hostname):
        return self._certPath(hostname).isfile()
