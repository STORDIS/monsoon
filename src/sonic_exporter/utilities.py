# Copyright 2021 STORDIS GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from concurrent.futures import ThreadPoolExecutor
import functools
from datetime import datetime, timedelta
import ipaddress
import logging
import logging.config
import os
from pathlib import Path
import socket

import yaml

from .constants import TRUE_VALUES

developer_mode = os.environ.get("DEVELOPER_MODE", "False").lower() in TRUE_VALUES

thread_pool = ThreadPoolExecutor(20)


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


@timed_cache(seconds=600)
def dns_lookup(ip: str) -> str:
    if ip is None:
        return ""
    try:
        ipaddress.ip_address(ip)
        return socket.gethostbyaddr(ip)[0]
    except (ValueError, socket.herror):
        return ip


BASE_PATH = Path(__file__).parent

_logging_initialized = False


def get_logger():
    global _logging_initialized
    if not _logging_initialized:
        logging_config_path = os.environ.get(
            "SONIC_EXPORTER_LOGGING_CONFIG",
            (BASE_PATH / "./config/logging.yml").resolve(),
        )
        LOGGING_CONFIG_RAW = ""
        with open(logging_config_path, "r") as file:
            LOGGING_CONFIG_RAW = file.read()
        loglevel = os.environ.get("SONIC_EXPORTER_LOGLEVEL", None)
        LOGGING_CONFIG = yaml.safe_load(LOGGING_CONFIG_RAW)
        if (
            loglevel
            and "handlers" in LOGGING_CONFIG
            and "console" in LOGGING_CONFIG["handlers"]
            and "level" in LOGGING_CONFIG["handlers"]["console"]
        ):
            LOGGING_CONFIG["handlers"]["console"]["level"] = loglevel
        logging.config.dictConfig(LOGGING_CONFIG)
        _logging_initialized = True
    return logging
