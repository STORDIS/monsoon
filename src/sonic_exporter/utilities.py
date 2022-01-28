import functools
import shutil
from datetime import datetime, timedelta


def frr_installed():
    command = "vtysh"
    return shutil.which(command) is not None


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
