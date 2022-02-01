COUNTER_PORT_MAP = "COUNTERS_PORT_NAME_MAP"
COUNTER_QUEUE_MAP = "COUNTERS_QUEUE_NAME_MAP"
COUNTER_QUEUE_TYPE_MAP = "COUNTERS_QUEUE_TYPE_MAP"
COUNTER_TABLE_PREFIX = "COUNTERS:"

COUNTER_IGNORE = ["cpu"]

FAN_INFO = "FAN_INFO|"
FAN_INFO_PATTERN = f"*{FAN_INFO}*"

PROCESS_STATS = "PROCESS_STATS|"
PROCESS_STATS_PATTERN = f"*{PROCESS_STATS}*"
PROCESS_STATS_IGNORE = ["lastupdatetime"]

PSU_INFO = "PSU_INFO|"
PSU_INFO_PATTERN = f"*{PSU_INFO}PSU*"

PORT_TABLE_PREFIX = "PORT_TABLE:"

SAG = "SAG|"
SAG_GLOBAL = "SAG_GLOBAL|IP"
SAG_PATTERN = f"*{SAG}*"

TEMPERATURE_INFO = "TEMPERATURE_INFO|"
TEMPERATURE_INFO_PATTERN = f"*{TEMPERATURE_INFO}*"

TRANSCEIVER_DOM_SENSOR = "TRANSCEIVER_DOM_SENSOR|"
TRANSCEIVER_DOM_SENSOR_PATTERN = f"*{TRANSCEIVER_DOM_SENSOR}*"

TRANSCEIVER_INFO = "TRANSCEIVER_INFO|"
TRANSCEIVER_INFO_PATTERN = f"*{TRANSCEIVER_INFO}Ethernet*"

## Values which mean "True"
TRUE_VALUES = ["up", "enable", "enabled", "true", "ready", "established", "1", 1]
##

VLAN_INTERFACE = "VLAN_INTERFACE|"

VXLAN_TUNNEL_TABLE = "VXLAN_TUNNEL_TABLE|"
VXLAN_TUNNEL_TABLE_PATTERN = f"*{VXLAN_TUNNEL_TABLE}*"

VXLAN_TUNNEL_MAP = "VXLAN_TUNNEL_MAP|"
VXLAN_TUNNEL_MAP_PATTERN = f"*{VXLAN_TUNNEL_MAP}*"