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
import re
import json
import time
import prometheus_client as prom
import swsssdk
import os
import subprocess
import sys
import logging
import logging.handlers

COUNTER_PORT_MAP = "COUNTERS_PORT_NAME_MAP"
COUNTER_QUEUE_MAP = "COUNTERS_QUEUE_NAME_MAP"
COUNTER_QUEUE_TYPE_MAP = "COUNTERS_QUEUE_TYPE_MAP"
COUNTER_TABLE_PREFIX = "COUNTERS:"

logger = logging.getLogger("Python_exporter")
fh = logging.handlers.RotatingFileHandler("/var/log/python_exporter.log", maxBytes=50000000, backupCount=3)
formatter = logging.Formatter('[%(asctime)s][%(levelname)s][%(name)s] %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
level = os.environ.get("PYTHON_EXPORTER_LOGLEVEL", "INFO")
logger.setLevel(level)

def _decode(string):
    if hasattr(string, "decode"):
        return string.decode("utf-8")
    return string

class Export:
    def __init__(self):
        try :
            secret = os.environ.get('REDIS_AUTH')
            logger.debug(f"Password from ENV: {secret}")
        except :
            logger.error("Password ENV REDIS_AUTH is not set ... Exiting")
            sys.exit(1)

        self.sonic_db = swsssdk.SonicV2Connector(password=secret)
        self.sonic_db.connect(self.sonic_db.COUNTERS_DB)
        self.sonic_db.connect(self.sonic_db.STATE_DB)
        self.sonic_db.connect(self.sonic_db.CONFIG_DB)
        self.curr_time = time.time()
        self.rx_octets_dict = {}
        self.tx_octets_dict = {}
        self._init_metrics()

    def _init_metrics(self):
        self.counter_zero = {}
        self.queue_counter_zero = {}
        # at start of server get counters data and negate it with current data while exporting
        self.intf_counter_reset()
        self.intf_queue_counter_reset()

        self.metric_intf_util_bps = prom.Gauge(
            "sonic_interface_util_bps",
            "Interface current utilization",
            ["interface_name", "util_type"],
        )
        self.metric_intf_counter = prom.Gauge(
            "sonic_interface_counters_packets",
            "Interface Counters",
            ["interface_name", "counter_type"],
        )
        self.metric_intf_queue_counter = prom.Gauge(
            "sonic_interface_queue_counters_packets",
            "Interface queue counters",
            ["interface_name", "queue_type"],
        )
        self.metric_intf_err_counter = prom.Gauge(
            "sonic_interface_error_counters_packets",
            "RX_ERR and TX_ERR for all the interfaces",
            ["interface_name", "error_type"],
        )
        self.metric_intf_power = prom.Gauge(
            "sonic_interface_power_dbm",
            "Power value for all the interfaces",
            ["interface_name", "power_type"],
        )
        self.metric_intf_voltage = prom.Gauge(
            "sonic_interface_voltage_volts",
            "Voltage of all the interfaces",
            ["interface_name"],
        )
        self.metric_intf_temp = prom.Gauge(
            "sonic_interface_temperature_celsius",
            "Temperature of all the interfaces",
            ["interface_name"],
        )
        self.metric_intf_cable = prom.Gauge(
            "sonic_interface_cable_length",
            "Cable details for all the interfaces",
            ["interface_name", "cable_type"],
        )
        self.metric_psu = prom.Gauge(
            "sonic_env_power_usage_mw",
            "RX_OK and TX_OK for all the interfaces",
            ["psu_name", "power_type"],
        )
        self.sys_info = prom.Info(
            "sonic_system",
            "part name, serial number, MAC address and software vesion of the System",
        )

        self.metric_bgp_peer_status = prom.Enum(
            "sonic_bgp_peer_status",
            "Interface current utilization",
            ["peer_name", "status"],
            states=["up", "down"],
        )

        self.metric_bgp_num_routes = prom.Gauge(
            "sonic_bgp_num_routes",
            "Interface current utilization",
            ["peer_name"],
        )

        self.metric_system_top10_cpu_percent = prom.Gauge(
            "sonic_system_top10_cpu_percent",
            "system top 10 process as per cpu usage",
            ["pid", "process_name"],
        )

        self.metric_system_top10_mem_percent = prom.Gauge(
            "sonic_system_top10_mem_percent",
            "system top 10 process as per mem usage",
            ["pid", "process_name"],
        )

    def export_intf_util_bps(self, ifname, RX_OCTETS, TX_OCTETS, delta):
        if ifname.lower() == "cpu":
            return
        RX_OCTETS_old = self.rx_octets_dict[ifname]
        TX_OCTETS_old = self.tx_octets_dict[ifname]
        logger.debug(
            "export_intf_util_bps :ifname={}, RX_OCTETS={}, TX_OCTETS={}, RX_OCTETS_old={}, TX_OCTETS_old={}, delta={}".format(ifname,RX_OCTETS,TX_OCTETS,RX_OCTETS_old,TX_OCTETS_old,delta)
        )  # 12 12 487830 491425 10
        if RX_OCTETS > RX_OCTETS_old and delta != 0:
            rx_bps = round(((RX_OCTETS - RX_OCTETS_old) / delta), 2)
        else:
            rx_bps = 0
        if TX_OCTETS > TX_OCTETS_old and delta != 0:
            tx_bps = round(((TX_OCTETS - TX_OCTETS_old) / delta), 2)
        else:
            tx_bps = 0

        self.rx_octets_dict[ifname] = RX_OCTETS
        self.tx_octets_dict[ifname] = TX_OCTETS

        logger.debug("export_intf_util_bps : rx_bps={} tx_bps={}".format(rx_bps, tx_bps))

        self.metric_intf_util_bps.labels(ifname, "RX").set(rx_bps)
        self.metric_intf_util_bps.labels(ifname, "TX").set(tx_bps)

    def intf_counter_reset(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            try:
                self.counter_zero[ifname, "RX_OK"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                    )
                ) + int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "RX_OK"] = 0
            try:
                self.counter_zero[ifname, "TX_OK"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                    )
                ) + int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "TX_OK"] = 0
            try:
                self.counter_zero[ifname, "RX_ERR"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_ERRORS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "RX_ERR"] = 0
            try:
                self.counter_zero[ifname, "TX_ERR"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_ERRORS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "TX_ERR"] = 0

            self.rx_octets_dict[ifname] = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB, counter_key, "SAI_PORT_STAT_IF_IN_OCTETS"
                )
            )
            self.tx_octets_dict[ifname] = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    counter_key,
                    "SAI_PORT_STAT_IF_OUT_OCTETS",
                )
            )

    def intf_queue_counter_reset(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            try:
                self.queue_counter_zero[ifname, "QUEUE_STAT_PACKET"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB, counter_key, "SAI_QUEUE_STAT_PACKETS"
                    )
                )
            except ValueError:
                self.queue_counter_zero[ifname, "QUEUE_STAT_PACKET"] = 0

    def export_intf_counter(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        old_time = self.curr_time
        logger.debug("export_intf_counter : old_time ", old_time)
        self.curr_time = time.time()
        logger.debug("export_intf_counter : self.curr_time ", self.curr_time)
        delta = int(self.curr_time - old_time)
        logger.debug("export_intf_counter : delta ", delta)
        for ifname in maps:
            if ifname.lower() == "cpu":
                continue
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            try:
                RX_OK = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                        )
                    )
                    + int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS",
                        )
                    )
                    - self.counter_zero[ifname, "RX_OK"]
                )
            except ValueError:
                RX_OK = 0
            try:
                TX_OK = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                        )
                    )
                    + int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",
                        )
                    )
                    - self.counter_zero[ifname, "TX_OK"]
                )
            except ValueError:
                TX_OK = 0
            try:
                RX_ERR = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_IN_ERRORS",
                        )
                    )
                    - self.counter_zero[ifname, "RX_ERR"]
                )
            except ValueError:
                RX_ERR = 0
            try:
                TX_ERR = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_OUT_ERRORS",
                        )
                    )
                    - self.counter_zero[ifname, "TX_ERR"]
                )
            except ValueError:
                TX_ERR = 0

            RX_OCTETS = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB, counter_key, "SAI_PORT_STAT_IF_IN_OCTETS"
                )
            )
            TX_OCTETS = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    counter_key,
                    "SAI_PORT_STAT_IF_OUT_OCTETS",
                )
            )

            self.metric_intf_counter.labels(ifname, "RX_OK").set(RX_OK)
            self.metric_intf_counter.labels(ifname, "TX_OK").set(TX_OK)
            self.metric_intf_err_counter.labels(ifname, "RX").set(RX_ERR)
            self.metric_intf_err_counter.labels(ifname, "TX").set(TX_ERR)
            self.export_intf_util_bps(ifname, RX_OCTETS, TX_OCTETS, delta)
            logger.debug("export_intf_counter : ifname={}, RX_OK={}, TX_OK={}, RX_ERR={}, TX_ERR={}".format(ifname, RX_OK, TX_OK, RX_ERR, TX_ERR))

    def export_intf_queue_counters(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            packet_type = _decode(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    COUNTER_QUEUE_TYPE_MAP,
                    _decode(maps[ifname]),
                )
            )
            ifname = _decode(ifname)
            try:
                QUEUE_STAT_PACKET = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_QUEUE_STAT_PACKETS",
                        )
                    )
                    - self.queue_counter_zero[ifname, "QUEUE_STAT_PACKET"]
                )
            except ValueError:
                QUEUE_STAT_PACKET = 0
            queue_type = "N/A"
            lane_no = ifname.split(":")[1]
            ifname = ifname.split(":")[0]
            if packet_type.endswith("MULTICAST"):
                queue_type = "MC" + lane_no
            if packet_type.endswith("UNICAST"):
                queue_type = "UC" + lane_no
            logger.debug("export_intf_queue_counters : ifname={}, queue_type={}, QUEUE_STAT_PACKET={}".format(ifname, queue_type, QUEUE_STAT_PACKET))
            self.metric_intf_queue_counter.labels(ifname, queue_type).set(
                QUEUE_STAT_PACKET
            )

    def export_intf_sensor_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern="*TRANSCEIVER_DOM_SENSOR*"
        )
        logger.debug("export_intf_sensor_data : keys={}".format(keys))
        for key in keys:
            ifname = _decode(key).replace("TRANSCEIVER_DOM_SENSOR|", "")
            transceiver_sensor_data = self.sonic_db.get_all(self.sonic_db.STATE_DB, key)
            for measure in transceiver_sensor_data:
                measure_dec = _decode(measure)
                if bool(re.match("^rx[0-9]*power$", measure_dec)):
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_power.labels(ifname, measure_dec).set(
                            float(value)
                        )
                    except ValueError:
                        self.metric_intf_power.labels(ifname, measure_dec).set(0)
                if bool(re.match("^tx[0-9]*power$", measure_dec)):
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_power.labels(ifname, measure_dec).set(
                            float(value)
                        )
                    except ValueError:
                        self.metric_intf_power.labels(ifname, measure_dec).set(0)
                if measure_dec == "voltage":
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_voltage.labels(ifname).set(float(value))
                    except ValueError:
                        self.metric_intf_voltage.labels(ifname).set(0)
                if measure_dec == "temperature":
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_temp.labels(ifname).set(float(value))
                    except ValueError:
                        self.metric_intf_temp.labels(ifname).set(0)

    def export_intf_cable_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern="*TRANSCEIVER_INFO|Ethernet*"
        )
        for key in keys:
            ifname = _decode(key).replace("TRANSCEIVER_INFO|", "")
            CABLE_TYPE = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "Connector")
            )
            try:
                CABLE_LEN = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "cable_length")
                )
            except ValueError and TypeError:
                CABLE_LEN = 0
            self.metric_intf_cable.labels(ifname, CABLE_TYPE).set(CABLE_LEN)

    def export_psu_info(self):
        keys = self.sonic_db.keys(self.sonic_db.STATE_DB, pattern="PSU_INFO|PSU*")
        for key in keys:
            psu_name = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "name"))
            try:
                in_power = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "input_power")
                )
            except ValueError and TypeError:
                in_power = 0
            try:
                out_power = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "output_power")
                )
            except ValueError and TypeError:
                out_power = 0
            logger.debug("export_psu_info : psu_name={}, in_power={}, out_power={}".format(psu_name, in_power, out_power))
            # multiply with 1000 for unit to be in mW
            self.metric_psu.labels(psu_name, "input").set(in_power*1000) 
            self.metric_psu.labels(psu_name, "output").set(out_power*1000)

    def _get_sonic_version_info(self):
        version = ""
        try :
            version = os.environ.get('SONIC_VERSION')
            logger.debug(f"sonic version from env: {version}")
        except :
            logger.error("ENV SONIC_VERSION is not set !. Set env in container to get software version in system info metric.")
            return ""
        return "SONiC-OS-{}".format(version)

    def export_sys_info(self):
        part_num = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x22", "Value")
        )
        serial_num = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x23", "Value")
        )
        mac_addr = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x24", "Value")
        )
        software_version = self._get_sonic_version_info()

        self.sys_info.info(
            {
                "part_number": part_num,
                "serial_number": serial_num,
                "mac_address": mac_addr,
                "software_version" : software_version,
            }
        )
        logger.debug("export_sys_info : part_num={}, serial_num={}, mac_addr={}, software_version={}".format(part_num, serial_num, mac_addr, software_version))

    def export_bgp_peer_status(self):
        # vtysh -c "show ip bgp neighbors Ethernet32 json"
        # get - bgpState and bgpTimerUp (available only when interface is up)
        try:
            keys = self.sonic_db.keys(self.sonic_db.CONFIG_DB, pattern="BGP_NEIGHBOR|default|*")
            for key in keys:
                key = _decode(key)
                bgp_neighbour = key.split("|")[-1]  # eg Ethernet32
                command = 'vtysh -c "show ip bgp neighbors {} json"'.format(
                    bgp_neighbour
                )
                logger.debug("export_bgp_peer_status : command out={}".format(subprocess.getoutput(command)))
                cmd_out = json.loads(subprocess.getoutput(command))
                
                # to handle any BGP_NEIGHBOR defined in redis but not found in vtysh
                if "bgpNoSuchNeighbor" in cmd_out.keys():
                    continue

                bgpState = cmd_out[bgp_neighbour]["bgpState"]
                # states as one of these - "idle","connect","active","opensent","openconfirm","Established"
                try:
                    _ = int(cmd_out[bgp_neighbour]["bgpTimerUp"])
                    self.metric_bgp_peer_status.labels(bgp_neighbour, bgpState).state(
                        "up"
                    )
                except KeyError:
                    self.metric_bgp_peer_status.labels(bgp_neighbour, bgpState).state(
                        "down"
                    )
        except Exception as e:
            logger.error("export_bgp_peer_status : Exception={}".format(e))

    def export_bgp_num_routes(self):
        # vtysh -c "show ip bgp neighbors Ethernet32 prefix-counts  json"
        # get - pfxCounter
        try:
            keys = self.sonic_db.keys(self.sonic_db.CONFIG_DB, pattern="BGP_NEIGHBOR|default|*")
            for key in keys:
                key = _decode(key)
                bgp_neighbour = key.split("|")[-1]  # eg Ethernet32
                command = (
                    'vtysh -c "show ip bgp neighbors {} prefix-counts json"'.format(
                        bgp_neighbour
                    )
                )
                logger.debug("export_bgp_num_routes : command out={}".format(subprocess.getoutput(command)))
                cmd_out = json.loads(subprocess.getoutput(command))
                # to handle any BGP_NEIGHBOR defined in redis but not found in vtysh
                if "malformedAddressOrName" in cmd_out.keys():
                    continue

                bgp_count = cmd_out["pfxCounter"]
                self.metric_bgp_num_routes.labels(bgp_neighbour).set(bgp_count)
        except Exception as e:
            logger.error("export_bgp_num_routes : Exception={}".format(e))

    def export_system_top10_process(self):
        # read "/usr/local/include/top_process.json" file and get the top process
        try:
            with open("/usr/local/include/top_process.json", "r") as f:
                top_process = json.loads(f.read())
                for cpu_process in top_process["top10_cpu_process"]:
                    self.metric_system_top10_cpu_percent.labels(
                        cpu_process["pid"], cpu_process["cmd"]
                    ).set(cpu_process["cpu_per"])

                for mem_process in top_process["top10_mem_process"]:
                    self.metric_system_top10_mem_percent.labels(
                        mem_process["pid"], mem_process["cmd"]
                    ).set(mem_process["mem_per"])
        except Exception as e:
            logger.error("export_system_top10_process : Exception={}".format(e))

    def start_export(self):
        try:
            self.export_intf_counter()
            self.export_intf_queue_counters()
            self.export_intf_cable_data()
            self.export_intf_sensor_data()
            self.export_sys_info()
            self.export_psu_info()
            self.export_bgp_peer_status()
            self.export_bgp_num_routes()
            self.export_system_top10_process()
        except Exception as e:
            logger.error("Exception={}".format(e))


def main():
    data_extract_interval = int(os.environ.get("REDIS_COLLECTION_INTERVAL", 30)) # considering 30 seconds as default collection interval
    port = 9101 #setting port static as 9101. if required map it to someother port of host by editing compose file.

    exp = Export()
    logger.info("Starting Python exporter server at port 9101")
    prom.start_http_server(port)
    while True:
        exp.start_export()
        time.sleep(data_extract_interval)


if __name__ == "__main__":
    file_path = os.path.dirname(__file__)
    if file_path != "":
        os.chdir(file_path)
    main()
