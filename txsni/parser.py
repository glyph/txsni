
from os.path import expanduser

from zope.interface import implementer

from twisted.internet.interfaces import IStreamServerEndpointStringParser
from twisted.internet.endpoints import serverFromString
from twisted.plugin import IPlugin

from txsni.snimap import SNIMap
from txsni.maputils import Cache
from txsni.snimap import HostDirectoryMap
from twisted.python.filepath import FilePath
from txsni.tlsendpoint import TLSEndpoint

@implementer(IStreamServerEndpointStringParser,
             IPlugin)
class SNIDirectoryParser(object):
    prefix = 'txsni'

    def parseStreamServer(self, reactor, pemdir, *args, **kw):
        def colonJoin(items):
            return ':'.join([item.replace(':', '\\:') for item in items])
        sub = colonJoin(list(args) + ['='.join(item) for item in kw.items()])
        subEndpoint = serverFromString(reactor, sub)
        contextFactory = SNIMap(
            Cache(HostDirectoryMap(FilePath(expanduser(pemdir))))
        )
        return TLSEndpoint(endpoint=subEndpoint,
                           contextFactory=contextFactory)

