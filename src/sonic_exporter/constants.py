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

from .enums import AirFlow, SwitchModel


def GET_PATTERN(data: str) -> str:
    return f"*{data}*"


CHASSIS_INFO = "CHASSIS_INFO|"
CHASSIS_INFO_PATTERN = GET_PATTERN(CHASSIS_INFO)

MCLAG_DOMAIN = "MCLAG_DOMAIN|"
MCLAG_DOMAIN_PATTERN = GET_PATTERN(MCLAG_DOMAIN)

MCLAG_TABLE = "MCLAG_TABLE|"
MCLAG_TABLE_PATTERN = GET_PATTERN(MCLAG_TABLE)

NTP_SERVER = "NTP_SERVER|"
NTP_SERVER_PATTERN = GET_PATTERN(NTP_SERVER)

COUNTER_PORT_MAP = "COUNTERS_PORT_NAME_MAP"
COUNTER_QUEUE_MAP = "COUNTERS_QUEUE_NAME_MAP"
COUNTER_QUEUE_TYPE_MAP = "COUNTERS_QUEUE_TYPE_MAP"
COUNTER_TABLE_PREFIX = "COUNTERS:"

COUNTER_IGNORE = ["cpu"]

EEPROM_INFO = "EEPROM_INFO|"
EEPROM_INFO_PATTERN = GET_PATTERN(EEPROM_INFO)

FAN_INFO = "FAN_INFO|"
FAN_INFO_PATTERN = GET_PATTERN(FAN_INFO)

PROCESS_STATS = "PROCESS_STATS|"
PROCESS_STATS_PATTERN = GET_PATTERN(PROCESS_STATS)
PROCESS_STATS_IGNORE = ["lastupdatetime"]

PSU_INFO = "PSU_INFO|"
PSU_INFO_PATTERN = GET_PATTERN(f"{PSU_INFO}PSU")

PORT_TABLE_PREFIX = "PORT_TABLE:"

SAG = "SAG|"
SAG_GLOBAL = "SAG_GLOBAL|IP"
SAG_PATTERN = GET_PATTERN(SAG)

TEMPERATURE_INFO = "TEMPERATURE_INFO|"
TEMPERATURE_INFO_PATTERN = GET_PATTERN(TEMPERATURE_INFO)

TRANSCEIVER_DOM_SENSOR = "TRANSCEIVER_DOM_SENSOR|"
TRANSCEIVER_DOM_SENSOR_PATTERN = GET_PATTERN(TRANSCEIVER_DOM_SENSOR)

TRANSCEIVER_INFO = "TRANSCEIVER_INFO|"
TRANSCEIVER_INFO_PATTERN = GET_PATTERN(f"{TRANSCEIVER_INFO}Ethernet")

## Values which mean "True"
TRUE_VALUES = [
    "up",
    "enable",
    "green",
    "enabled",
    "true",
    "ready",
    "established",
    "1",
    1,
]
##

VLAN_INTERFACE = "VLAN_INTERFACE|"

VXLAN_TUNNEL_TABLE = "VXLAN_TUNNEL_TABLE|"
VXLAN_TUNNEL_TABLE_PATTERN = GET_PATTERN(VXLAN_TUNNEL_TABLE)

VXLAN_TUNNEL_MAP = "VXLAN_TUNNEL_MAP|"
VXLAN_TUNNEL_MAP_PATTERN = GET_PATTERN(VXLAN_TUNNEL_MAP)


# Informative:
# pcb == mostly the middle sensor on the dataplane logic board
# environment = The sensor which is mostly located on the side of the switch.
TEMP_SENSORS = {
    SwitchModel.AS7326: {
        AirFlow.BACK_TO_FRONT: {
            "4a": "environment",
            "4b": "intake",
            "48": "pcb",
            "49": "exhaust",
        },
        AirFlow.FRONT_TO_BACK: {
            "4a": "environment",
            "4b": "exhaust",
            "48": "pcb",
            "49": "intake",
        },
    },
    SwitchModel.AS7726: {
        AirFlow.BACK_TO_FRONT: {
            "4a": "environment",
            "4b": "intake cpu",
            "4c": "intake",
            "48": "pcb",
            "49": "exhaust",
        },
        AirFlow.FRONT_TO_BACK: {
            "4a": "environment",
            "4b": "exhaust cpu",
            "4c": "exhaust",
            "48": "pcb",
            "49": "intake",
        },
    },
    SwitchModel.AS5853: {
        AirFlow.BACK_TO_FRONT: {
            "4a": "pcb",
            "4b": "intake",
            "4c": "exhaust",
            "49": "environment",
        },
        AirFlow.FRONT_TO_BACK: {
            "4a": "pcb",
            "4b": "exhaust",
            "4c": "intake",
            "49": "environment",
        },
    },
    SwitchModel.AS9716: {
        AirFlow.BACK_TO_FRONT: {
            "4a": "environment cpu",
            "4b": "intake",
            "4c": "exhaust cpu",
            "4e": "intake cpu",
            "4f": "environment",
            "48": "exhaust",
            "49": "pcb",
        },
        AirFlow.FRONT_TO_BACK: {
            "4a": "environment cpu",
            "4b": "exhaust",
            "4c": "intake cpu",
            "4e": "exhaust cpu",
            "4f": "environment",
            "48": "intake",
            "49": "pcb",
        },
    },
}
