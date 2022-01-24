from enum import Enum
import json
import re
from importlib.resources import read_text
from . import ressources


class SwitchModel(Enum):
    AS7326 = "x86_64-accton_as7326_56x-r0"
    AS7726 = "x86_64-accton_as7726_32x-r0"


class SonicV2Connector:
    class DB(Enum):
        APPL_DB = "appl"
        ASIC_DB = "asic"
        COUNTERS_DB = "counters"
        LOGLEVEL_DB = "loglevel"
        CONFIG_DB = "config"
        PFC_WD_DB = "pfc_wd"
        STATE_DB = "state"
        SNMP_OVERLAY_DB = "snmp_overlay"
        ERROR_DB = "error"

    APPL_DB = DB.APPL_DB
    ASIC_DB = DB.ASIC_DB
    COUNTERS_DB = DB.COUNTERS_DB
    LOGLEVEL_DB = DB.LOGLEVEL_DB
    CONFIG_DB = DB.CONFIG_DB
    PFC_WD_DB = DB.PFC_WD_DB
    STATE_DB = DB.STATE_DB
    SNMP_OVERLAY_DB = DB.SNMP_OVERLAY_DB
    ERROR_DB = DB.ERROR_DB

    @staticmethod
    def load_db(model: SwitchModel, db: DB):
        return json.loads(read_text(ressources, f"{model.value}.{db.value}.json"))

    def __init__(self, password: str, model: SwitchModel = SwitchModel.AS7326):
        self.password = password
        self.model = model
        self.db = {}

    def connect(self, db: DB):
        self.db = {**self.db, **{db: self.load_db(self.model, db)}}

    def get_all(self, db: DB, key: str):
        return self.db[db][key]["value"]

    def get(self, db: DB, key: str, sub_key: str):
        return self.db[db][key]["value"][sub_key]

    def keys(self, db: DB, pattern: str = None):
        regex = re.compile(
            r"^{}$".format(pattern.replace("*", ".*?").replace("|", "\|"))
        )
        for key in self.db[db].keys():
            if regex.match(str(key)):
                yield key
