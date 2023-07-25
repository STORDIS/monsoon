import time
from exporter import developer_mode

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


def getFromDB(
    self, db_name, hash, key, retries=db_default_retries, timeout=db_default_timeout
):
    for i in range(0, retries):
        keys = self.sonic_db.get(db_name, hash, key)
        if keys == None:
            self.logger.debug(
                "Couldn't retrieve {0} from hash {1} from db {2}.".format(
                    key, hash, db_name
                )
            )
            if i < retries - 1:
                self.logger.debug("Retrying in {0} secs.".format(timeout))
                time.sleep(timeout)
                continue
        return keys

def getKeysFromDB(
    self, db_name, patrn, retries=db_default_retries, timeout=db_default_timeout
):
    for i in range(0, retries):
        keys = self.sonic_db.keys(db_name, pattern=patrn)
        if keys == None:
            self.logger.debug(
                "Couldn't retrieve {0} from {1}.".format(patrn, db_name)
            )
            if i < retries - 1:
                self.logger.debug("Retrying in {0} secs.".format(timeout))
                time.sleep(timeout)
        else:
            # self.logger.info("Finally retrieved values")
            return keys
    self.logger.debug(
        "Couldn't retrieve {0} from {1}, after {2} retries returning no results.".format(
            patrn, db_name, retries
        )
    )
    # return empty array instead of NoneType
    return []

def getAllFromDB(
    self, db_name, hash, retries=db_default_retries, timeout=db_default_timeout
):
    for i in range(0, retries):
        keys = self.sonic_db.get_all(db_name, hash)
        if keys == None:
            self.logger.debug(
                "Couldn't retrieve hash {0} from db {1}.".format(hash, db_name)
            )
            if i < retries - 1:
                self.logger.debug("Retrying in {0} secs.".format(timeout))
                time.sleep(timeout)
        else:
            return keys
    self.logger.debug(
        "Couldn't retrieve hash {0} from db {1}, after {2} retries.".format(
            hash, db_name, retries
        )
    )
    # return empty array instead of NoneType
    return []
