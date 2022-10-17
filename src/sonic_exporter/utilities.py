from distutils.version import Version
import functools
import re
from datetime import datetime, timedelta


def timed_cache(**timedelta_kwargs):
    def _wrapper(f):
        maxsize = timedelta_kwargs.pop("maxsize", 128)
        typed = timedelta_kwargs.pop("typed", False)
        update_delta = timedelta(**timedelta_kwargs)
        next_update = datetime.utcnow() - update_delta
        # Apply @lru_cache to f
        f = functools.lru_cache(maxsize=maxsize, typed=typed)(f)

        @functools.wraps(f)
        def _wrapped(*args, **kwargs):
            timed_cache_clear()
            return f(*args, **kwargs)

        def timed_cache_clear():
            """Clear cache when time expires"""
            nonlocal next_update
            now = datetime.utcnow()
            if now >= next_update:
                f.cache_clear()
                next_update = now + update_delta

        def cache_info():
            """Report cache statistics"""
            timed_cache_clear()
            return f.cache_info()

        _wrapped.cache_info = cache_info
        _wrapped.cache_clear = f.cache_clear
        return _wrapped

    return _wrapper


class ConfigDBVersion(Version):

    component_re = re.compile(r"(\d+|_)", re.VERBOSE)
    vstring = ""
    version = []

    def parse(self, vstring):
        # I've given up on thinking I can reconstruct the version string
        # from the parsed tuple -- so I just store the string here for
        # use by __str__
        self.vstring = vstring
        components = [x for x in self.component_re.split(vstring) if x and x != "_"]
        for i, obj in enumerate(components):
            try:
                components[i] = int(obj)
            except ValueError:
                pass

        self.version = components

    def __str__(self):
        return self.vstring

    def __repr__(self):
        return "ConfigDBVersion ('{}')".format(self)

    def _cmp(self, other):
        if isinstance(other, str):
            other = ConfigDBVersion(other)
        elif not isinstance(other, ConfigDBVersion):
            return NotImplemented

        if self.version == other.version:
            return 0
        if self.version < other.version:
            return -1
        if self.version > other.version:
            return 1
