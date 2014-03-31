from twisted.protocols.tls import TLSMemoryBIOFactory

class TLSEndpoint(object):
    def __init__(self, endpoint, contextFactory):
        self.endpoint = endpoint
        self.contextFactory = contextFactory


    def listen(self, factory):
        return self.endpoint.listen(TLSMemoryBIOFactory(
            self.contextFactory, False, factory
        ))

