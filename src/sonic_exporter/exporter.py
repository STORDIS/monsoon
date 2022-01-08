#!/usr/bin/env python3
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
import prometheus_client.utils as promutils

try:
    import swsssdk
except ImportError:
    import sonic_exporter.test.mock_db as swsssdk
import os
import subprocess
import sys
import logging
import logging.handlers


class CustomCounter(prom.Counter):
    def set(self, value):
        """Set gauge to the given value."""
        self._raise_if_not_observable()
        self._value.set(float(value))

    def _child_samples(self):
        return (("_total", {}, self._value.get(), None, self._value.get_exemplar()),)


COUNTER_PORT_MAP = "COUNTERS_PORT_NAME_MAP"
COUNTER_QUEUE_MAP = "COUNTERS_QUEUE_NAME_MAP"
COUNTER_QUEUE_TYPE_MAP = "COUNTERS_QUEUE_TYPE_MAP"
COUNTER_TABLE_PREFIX = "COUNTERS:"

level = os.environ.get("SONIC_EXPORTER_LOGLEVEL", "INFO")
logging.basicConfig(
    encoding="utf-8",
    stream=sys.stdout,
    format="[%(asctime)s][%(levelname)s][%(name)s] %(message)s",
    level=logging.getLevelName(level),
)


def _decode(string):
    if hasattr(string, "decode"):
        return string.decode("utf-8")
    return string


class Export:
    def __init__(self):
        try:
            secret = os.environ.get("REDIS_AUTH")
            logging.debug(f"Password from ENV: {secret}")
        except KeyboardInterrupt as e:
            raise e
        except:
            logging.error("Password ENV REDIS_AUTH is not set ... Exiting")
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
        # at start of server get counters data and negate it with current data while exporting
        # Interface counters
        interface_labels = ["interface"]
        self.metric_interface_info = prom.Gauge(
            "sonic_interface_info",
            "Interface Information (Description, MTU, Speed)",
            interface_labels + ["description", "mtu", "speed"]
        )
        self.metric_interface_transmitted_bytes = CustomCounter(
            "sonic_interface_transmitted_bytes_total",
            "Total transmitted Bytes by Interface",
            interface_labels,
        )
        self.metric_interface_received_bytes = CustomCounter(
            "sonic_interface_received_bytes_total",
            "Total received Bytes by Interface",
            interface_labels,
        )
        self.metric_interface_transmitted_packets = CustomCounter(
            "sonic_interface_transmitted_packets_total",
            "Total transmitted Packets by Interface",
            interface_labels + ["delivery_mode"],
        )
        self.metric_interface_received_packets = CustomCounter(
            "sonic_interface_received_packets_total",
            "Total received Packets by Interface",
            interface_labels + ["delivery_mode"],
        )
        self.metric_interface_receive_error_input_packets = CustomCounter(
            "sonic_interface_receive_error_input_packets_total",
            "Errors in received packets",
            interface_labels + ["cause"],
        )
        self.metric_interface_transmit_error_output_packets = CustomCounter(
            "sonic_interface_transmit_error_output_packets_total",
            "Errors in transmitted packets",
            interface_labels + ["cause"],
        )
        self.metric_interface_received_ethernet_packets = CustomCounter(
            "sonic_interface_received_ethernet_packets",
            "Size of the Ethernet Frames received",
            interface_labels + ["packet_size"],
        )
        self.metric_interface_transmitted_ethernet_packets = CustomCounter(
            "sonic_interface_transmitted_ethernet_packets",
            "Size of the Ethernet Frames transmitted",
            interface_labels + ["packet_size"],
        )
        ## Queue Counters
        self.metric_interface_queue_processed_packets = CustomCounter(
            "sonic_interface_queue_processed_packets",
            "Interface queue counters",
            interface_labels + ["queue"] + ["delivery_mode"],
        )
        self.metric_interface_queue_processed_bytes = CustomCounter(
            "sonic_interface_queue_processed_bytes",
            "Interface queue counters",
            interface_labels + ["queue"] + ["delivery_mode"],
        )
        ## Health Information
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

        # self.metric_bgp_peer_status = prom.Enum(
        #     "sonic_bgp_peer_status",
        #     "Interface current utilization",
        #     ["peer_name", "status"],
        #     states=["up", "down"],
        # )

        # self.metric_bgp_num_routes = prom.Gauge(
        #     "sonic_bgp_num_routes",
        #     "Interface current utilization",
        #     ["peer_name"],
        # )

        # self.metric_system_top10_cpu_percent = prom.Gauge(
        #     "sonic_system_top10_cpu_percent",
        #     "system top10 process as per cpu percent",
        #     ["pid", "process_name"],
        # )

        # self.metric_system_top10_mem_percent = prom.Gauge(
        #     "sonic_system_top10_mem_percent",
        #     "system top10 process as per mem percent",
        #     ["pid", "process_name"],
        # )

    def get_portinfo(self, ifname, sub_key):
        if ifname.startswith("Ethernet"):
            key = f"PORT|{ifname}"
        else:
            key = f"PORTCHANNEL|{ifname}"
        try:
            return self.sonic_db.get(self.sonic_db.CONFIG_DB, key, sub_key)
        except (ValueError, KeyError):
            return ""

    def get_additional_info(self, ifname):
        return self.get_portinfo(ifname, "alias") or ifname

    def export_intf_counter(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        for ifname in maps:
            if ifname.lower() == "cpu":
                continue
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            self.metric_interface_info.labels(
                    self.get_additional_info(ifname),
                    self.get_portinfo(ifname, "description"),
                    self.get_portinfo(ifname, "mtu"),
                    f"{'{}Gbps'.format(int(round(int(self.get_portinfo(ifname, 'speed'))) / 1000)) if self.get_portinfo(ifname, 'speed') else ''}",
            ).set(1)
            ## RX
            self.metric_interface_received_bytes.labels(
                self.get_additional_info(ifname)
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_OCTETS",
                    )
                )
            )
            self.metric_interface_received_packets.labels(
                self.get_additional_info(ifname), "unicast"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                    )
                )
            )
            self.metric_interface_received_packets.labels(
                self.get_additional_info(ifname), "multicast"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS",
                    )
                )
            )
            self.metric_interface_received_packets.labels(
                self.get_additional_info(ifname), "broadcast"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS",
                    )
                )
            )
            for size, key in zip(
                (64, 127, 255, 511, 1023, 1518, 2047, 4095, 9216, 16383),
                [
                    "SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_2048_TO_4095_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_4096_TO_9216_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_9217_TO_16383_OCTETS",
                ],
            ):
                self.metric_interface_received_ethernet_packets.labels(
                    self.get_additional_info(ifname), size
                ).set(
                    int(self.sonic_db.get(self.sonic_db.COUNTERS_DB, counter_key, key))
                )
            ## RX Errors
            self.metric_interface_receive_error_input_packets.labels(
                self.get_additional_info(ifname), "error"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_ERRORS",
                    )
                )
            )
            self.metric_interface_receive_error_input_packets.labels(
                self.get_additional_info(ifname), "discard"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_DISCARDS",
                    )
                )
            )
            self.metric_interface_receive_error_input_packets.labels(
                self.get_additional_info(ifname), "drop"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IN_DROPPED_PKTS",
                    )
                )
            )
            self.metric_interface_receive_error_input_packets.labels(
                self.get_additional_info(ifname), "pause"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_RX_PKTS",
                    )
                )
            )
            ## TX
            self.metric_interface_transmitted_bytes.labels(
                self.get_additional_info(ifname)
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_OCTETS",
                    )
                )
            )
            self.metric_interface_transmitted_packets.labels(
                self.get_additional_info(ifname), "unicast"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                    )
                )
            )
            self.metric_interface_transmitted_packets.labels(
                self.get_additional_info(ifname), "multicast"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS",
                    )
                )
            )
            self.metric_interface_transmitted_packets.labels(
                self.get_additional_info(ifname), "broadcast"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS",
                    )
                )
            )
            for size, key in zip(
                (64, 127, 255, 511, 1023, 1518, 2047, 4095, 9216, 16383),
                [
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_2048_TO_4095_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_4096_TO_9216_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_9217_TO_16383_OCTETS",
                ],
            ):
                self.metric_interface_transmitted_ethernet_packets.labels(
                    self.get_additional_info(ifname), size
                ).set(
                    int(self.sonic_db.get(self.sonic_db.COUNTERS_DB, counter_key, key))
                )
            # SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS
            ## TX Errors
            self.metric_interface_transmit_error_output_packets.labels(
                self.get_additional_info(ifname), "error"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_ERRORS",
                    )
                )
            )
            self.metric_interface_transmit_error_output_packets.labels(
                self.get_additional_info(ifname), "discard"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_DISCARDS",
                    )
                )
            )
            self.metric_interface_transmit_error_output_packets.labels(
                self.get_additional_info(ifname), "pause"
            ).set(
                int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_TX_PKTS",
                    )
                )
            )
            logging.debug("export_intf_counter : ifname={}".format(ifname))

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
            QUEUE_STAT_PACKET = self.sonic_db.get(
                self.sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_PACKETS",
            )
            QUEUE_STAT_BYTE = self.sonic_db.get(
                self.sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_BYTES",
            )
            queue_type = "N/A"
            ifname, queue = ifname.split(":")
            if ifname.lower() == "cpu":
                continue
            if packet_type.endswith("MULTICAST"):
                queue_type = "multicast"
            if packet_type.endswith("UNICAST"):
                queue_type = "unicast"
            logging.debug(
                "export_intf_queue_counters : ifname={}, queue_type={}, QUEUE_STAT_PACKET={}".format(
                    ifname, queue_type, QUEUE_STAT_PACKET
                )
            )
            logging.debug(
                "export_intf_queue_counters : ifname={}, queue_type={}, QUEUE_STAT_BYTE={}".format(
                    ifname, queue_type, QUEUE_STAT_BYTE
                )
            )
            self.metric_interface_queue_processed_packets.labels(self.get_additional_info(ifname), queue, queue_type).set(QUEUE_STAT_PACKET)
            self.metric_interface_queue_processed_bytes.labels(self.get_additional_info(ifname), queue, queue_type).set(QUEUE_STAT_BYTE)

    def export_intf_sensor_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern="*TRANSCEIVER_DOM_SENSOR*"
        )
        logging.debug("export_intf_sensor_data : keys={}".format(keys))
        for key in keys:
            ifname = _decode(key).replace("TRANSCEIVER_DOM_SENSOR|", "")
            transceiver_sensor_data = self.sonic_db.get_all(self.sonic_db.STATE_DB, key)
            for measure in transceiver_sensor_data:
                measure_dec = _decode(measure)
                if bool(re.match("^rx[0-9]*power$", measure_dec)):
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_power.labels(measure_dec).set(float(value))
                    except ValueError:
                        self.metric_intf_power.labels(measure_dec).set(0)
                if bool(re.match("^tx[0-9]*power$", measure_dec)):
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_power.labels(measure_dec).set(float(value))
                    except ValueError:
                        self.metric_intf_power.labels(measure_dec).set(0)
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
            except (ValueError, TypeError):
                CABLE_LEN = 0
            self.metric_intf_cable.labels(CABLE_TYPE).set(CABLE_LEN)

    def export_psu_info(self):
        keys = self.sonic_db.keys(self.sonic_db.STATE_DB, pattern="PSU_INFO|PSU*")
        for key in keys:
            psu_name = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "name"))
            try:
                in_power = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "input_power")
                )
            except (ValueError, TypeError):
                in_power = 0
            try:
                out_power = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "output_power")
                )
            except (ValueError, TypeError):
                out_power = 0
            logging.debug(
                "export_psu_info : psu_name={}, in_power={}, out_power={}".format(
                    psu_name, in_power, out_power
                )
            )
            # multiply with 1000 for unit to be in mW
            self.metric_psu.labels(psu_name, "input").set(in_power * 1000)
            self.metric_psu.labels(psu_name, "output").set(out_power * 1000)

    def _get_sonic_version_info(self):
        version = ""
        try:
            version = os.environ.get("SONIC_VERSION")
            logging.debug(f"sonic version from env: {version}")
        except KeyboardInterrupt as e:
            raise e
        except:
            logging.error(
                "ENV SONIC_VERSION is not set !. Set env in container to get software version in system info metric."
            )
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
                "software_version": software_version,
            }
        )
        logging.debug(
            "export_sys_info : part_num={}, serial_num={}, mac_addr={}, software_version={}".format(
                part_num, serial_num, mac_addr, software_version
            )
        )

    def export_bgp_peer_status(self):
        # vtysh -c "show ip bgp neighbors Ethernet32 json"
        # get - bgpState and bgpTimerUp (available only when interface is up)
        try:
            keys = self.sonic_db.keys(
                self.sonic_db.CONFIG_DB, pattern="BGP_NEIGHBOR|default|*"
            )
            for key in keys:
                key = _decode(key)
                bgp_neighbour = key.split("|")[-1]  # eg Ethernet32
                command = 'vtysh -c "show ip bgp neighbors {} json"'.format(
                    bgp_neighbour
                )
                logging.debug(
                    "export_bgp_peer_status : command out={}".format(
                        subprocess.getoutput(command)
                    )
                )
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
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            logging.error("export_bgp_peer_status : Exception={}".format(e))

    def export_bgp_num_routes(self):
        # vtysh -c "show ip bgp neighbors Ethernet32 prefix-counts  json"
        # get - pfxCounter
        try:
            keys = self.sonic_db.keys(
                self.sonic_db.CONFIG_DB, pattern="BGP_NEIGHBOR|default|*"
            )
            for key in keys:
                key = _decode(key)
                bgp_neighbour = key.split("|")[-1]  # eg Ethernet32
                command = (
                    'vtysh -c "show ip bgp neighbors {} prefix-counts json"'.format(
                        bgp_neighbour
                    )
                )
                logging.debug(
                    "export_bgp_num_routes : command out={}".format(
                        subprocess.getoutput(command)
                    )
                )
                cmd_out = json.loads(subprocess.getoutput(command))
                # to handle any BGP_NEIGHBOR defined in redis but not found in vtysh
                if "malformedAddressOrName" in cmd_out.keys():
                    continue

                bgp_count = cmd_out["pfxCounter"]
                self.metric_bgp_num_routes.labels(bgp_neighbour).set(bgp_count)
        except KeyboardInterrupt as e:
            raise e
        except Exception as e:
            logging.error("export_bgp_num_routes : Exception={}".format(e))

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
        except KeyboardInterrupt as e:
            raise e
        except FileNotFoundError as e:
            logging.error("export_system_top10_process : Exception={}".format(e))

    def start_export(self):
        try:
            self.export_intf_counter()
            self.export_intf_queue_counters()
            self.export_intf_cable_data()
            self.export_intf_sensor_data()
            self.export_sys_info()
            self.export_psu_info()
            # self.export_bgp_peer_status()
            # self.export_bgp_num_routes()
            # self.export_system_top10_process()
        except KeyboardInterrupt as e:
            raise e


def main():
    data_extract_interval = int(
        os.environ.get("REDIS_COLLECTION_INTERVAL", 30)
    )  # considering 30 seconds as default collection interval
    port = 9101  # setting port static as 9101. if required map it to someother port of host by editing compose file.

    exp = Export()
    logging.info("Starting Python exporter server at port 9101")
    prom.start_http_server(port)

    while True:
        exp.start_export()
        time.sleep(data_extract_interval)


def cli():
    try:
        file_path = os.path.dirname(__file__)
        if file_path != "":
            os.chdir(file_path)
        main()
    except KeyboardInterrupt:
        sys.exit(0)
