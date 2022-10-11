import json
import re
from enum import Enum
from importlib.resources import read_text
from importlib import import_module

from sonic_exporter.enums import SwitchModel

from . import ressources


class SonicV2Connector:

    model: SwitchModel = SwitchModel.AS7326
    version: str = "3.5.0"

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
    def get_version(version: str):
        return f'v{version.replace(".", "_")}'

    @staticmethod
    def load_db(version: str, model: SwitchModel, db: DB):
        return json.loads(
            read_text(
                import_module(
                    f"{ressources.__package__}.{SonicV2Connector.get_version(version)}"
                ),
                f"{model.value}.{db.value}.json",
            )
        )

    def __init__(self, password: str):
        self.password = password
        self.db = {}

    def connect(self, db: DB):
        self.db = {**self.db, **{db: self.load_db(self.version, self.model, db)}}

    def get_all(self, db: DB, key: str):
        return self.db[db].get(key, {}).get("value", None)

    def get(self, db: DB, key: str, sub_key: str):
        return self.db[db][key]["value"].get(sub_key, None)

    def keys(self, db: DB, pattern: str = None):
        regex = re.compile(
            r"^{}$".format(pattern.replace("*", ".*?").replace("|", "\|"))
        )
        for key in self.db[db].keys():
            if regex.match(str(key)):
                yield key
