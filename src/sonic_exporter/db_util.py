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

from packaging.version import Version
from typing import List, Any
import re
from .converters import decode as _decode
from .utilities import developer_mode, get_logger

import time

_logger = get_logger().getLogger(__name__)

db_default_retries = 1
# timeout applicable only when retries >1
db_default_timeout = 3
# Non default values of retries and timeout are usefull for DB calls, when DB may not be ready to serve requests
# e.g. right after SONiC boots up while getting sonic system status from DB.

if developer_mode:
    import sonic_exporter.test.mock_db as mock_db

    sonic_db = mock_db.SonicV2Connector(password="")
else:
    import swsssdk

    try:
        with open("/run/redis/auth/passwd", "r") as secret:
            sonic_db = swsssdk.SonicV2Connector(password=secret.read().strip())
    except FileNotFoundError:
        sonic_db = swsssdk.SonicV2Connector()

sonic_db.connect(sonic_db.COUNTERS_DB)
sonic_db.connect(sonic_db.STATE_DB)
sonic_db.connect(sonic_db.APPL_DB)
sonic_db.connect(sonic_db.CONFIG_DB)


def getFromDB(
    db_name, hash, key, retries=db_default_retries, timeout=db_default_timeout
):
    for i in range(0, retries):
        keys = sonic_db.get(db_name, hash, key)
        if keys == None:
            _logger.debug(
                "Couldn't retrieve {0} from hash {1} from db {2}.".format(
                    key, hash, db_name
                )
            )
            if i < retries - 1:
                _logger.debug("Retrying in {0} secs.".format(timeout))
                time.sleep(timeout)
                continue
        return keys


def getKeysFromDB(
    db_name, patrn, retries=db_default_retries, timeout=db_default_timeout
):
    for i in range(0, retries):
        keys = sonic_db.keys(db_name, pattern=patrn)
        if keys == None:
            _logger.debug("Couldn't retrieve {0} from {1}.".format(patrn, db_name))
            if i < retries - 1:
                _logger.debug("Retrying in {0} secs.".format(timeout))
                time.sleep(timeout)
        else:
            return keys
    _logger.debug(
        "Couldn't retrieve {0} from {1}, after {2} retries returning no results.".format(
            patrn, db_name, retries
        )
    )
    # return empty array instead of NoneType
    return []


def getAllFromDB(db_name, hash, retries=db_default_retries, timeout=db_default_timeout):
    for i in range(0, retries):
        keys = sonic_db.get_all(db_name, hash)
        if keys == None:
            _logger.debug(
                "Couldn't retrieve hash {0} from db {1}.".format(hash, db_name)
            )
            if i < retries - 1:
                _logger.debug("Retrying in {0} secs.".format(timeout))
                time.sleep(timeout)
        else:
            return keys
    _logger.debug(
        "Couldn't retrieve hash {0} from db {1}, after {2} retries.".format(
            hash, db_name, retries
        )
    )
    # return empty array instead of NoneType
    return []


class ConfigDBVersion(Version):
    VERSION_PATTERN = re.compile(r"_", re.VERBOSE)

    def __init__(self, vstring: str | None = None) -> None:
        self.vstring = vstring
        self.version_representation = str(self.vstring).replace("version_", "", 1)
        self.version_representation = str(self.version_representation).replace("_", ".")
        super().__init__(self.version_representation)

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


db_version = ConfigDBVersion(
    _decode(getFromDB(sonic_db.CONFIG_DB, "VERSIONS|DATABASE", "VERSION", retries=15))
)


def is_sonic_sys_ready(retries=db_default_retries, timeout=db_default_timeout):
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
