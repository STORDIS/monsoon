import logging
from distutils.version import Version
from sonic_exporter.converters import decode as _decode

import time
from exporter import developer_mode
from test import mock_db
_logger = logging.getLogger(__name__)

db_default_retries = 1
    # timeout applicable only when retries >1
db_default_timeout = 3
# Non default values of retries and timeout are usefull for DB calls, when DB may not be ready to serve requests
# e.g. right after SONiC boots up while getting sonic system status from DB.
import swsssdk
if developer_mode:
    sonic_db = mock_db.SonicV2Connector(password="")
else:
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

def getKeysFromDB( db_name, patrn, retries=db_default_retries, timeout=db_default_timeout
):
    for i in range(0, retries):
        keys = sonic_db.keys(db_name, pattern=patrn)
        if keys == None:
            _logger.debug(
                "Couldn't retrieve {0} from {1}.".format(patrn, db_name)
            )
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

def getAllFromDB(db_name, hash, retries=db_default_retries, timeout=db_default_timeout
):
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
        
        
db_version = ConfigDBVersion(
    _decode(
        getFromDB(
            sonic_db.CONFIG_DB, "VERSIONS|DATABASE", "VERSION", retries=15
        )
    )
)