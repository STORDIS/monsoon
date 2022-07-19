from sonic_exporter.enums import AirFlow, SwitchModel


def GET_PATTERN(data: str) -> str:
    return f"*{data}*"


CHASSIS_INFO = "CHASSIS_INFO|"
CHASSIS_INFO_PATTERN = GET_PATTERN(CHASSIS_INFO)

COUNTER_PORT_MAP = "COUNTERS_PORT_NAME_MAP"
COUNTER_QUEUE_MAP = "COUNTERS_QUEUE_NAME_MAP"
COUNTER_QUEUE_TYPE_MAP = "COUNTERS_QUEUE_TYPE_MAP"
COUNTER_TABLE_PREFIX = "COUNTERS:"

COUNTER_IGNORE = ["cpu"]

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
}
