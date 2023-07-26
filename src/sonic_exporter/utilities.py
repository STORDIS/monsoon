import functools
from datetime import datetime, timedelta
import ipaddress
import socket
from db_util import db_default_retries, db_default_timeout, getFromDB,sonic_db,db_version,ConfigDBVersion


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


def is_sonic_sys_ready(
    retries=db_default_retries, timeout=db_default_timeout
):
    sts = getFromDB(
        sonic_db.STATE_DB,
        "SYSTEM_READY|SYSTEM_STATE",
        "Status",
        retries=retries,
        timeout=timeout,
    )
    sts_core = sts
    if db_version > ConfigDBVersion("version_4_0_0"):
        ## this feature is only supported in newer ConfigDBs
        ## Especially version_3_4_1 does not have this flag
        ## so we use the sts flag for backwards compatible code.
        sts_core = getFromDB(
            sonic_db.STATE_DB,
            "SYSTEM_READY_CORE|SYSTEM_STATE",
            "Status",
            retries=retries,
            timeout=timeout,
        )
    sts = True if sts and "UP" in sts else False
    sts_core = True if sts and "UP" in sts_core else False
    return sts, sts_core


@timed_cache(seconds=600)
def dns_lookup(ip: str) -> str:
    if ip is None:
        return ""
    try:
        ipaddress.ip_address(ip)
        return socket.gethostbyaddr(ip)[0]
    except (ValueError, socket.herror):
        return ip