

class Cache(object):

    def __init__(self, mapping):
        self.mapping = mapping
        self.cache = {}


    def __getitem__(self, key):
        if key in self.cache:
            return self.cache[key]
        else:
            value = self.mapping[key]
            self.cache[key] = value
            return value


