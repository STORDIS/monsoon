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
from sqlite3 import converters
import time
import prometheus_client as prom
import prometheus_client.utils as promutils

from sonic_exporter.constants import (
    COUNTER_IGNORE,
    COUNTER_PORT_MAP,
    COUNTER_QUEUE_MAP,
    COUNTER_QUEUE_TYPE_MAP,
    COUNTER_TABLE_PREFIX,
    FAN_INFO_PATTERN,
    PORT_TABLE_PREFIX,
    PROCESS_STATS_PATTERN,
    PSU_INFO,
    PSU_INFO_PATTERN,
    TEMPERATURE_INFO_PATTERN,
    TRANSCEIVER_DOM_SENSOR,
    TRANSCEIVER_DOM_SENSOR_PATTERN,
    TRANSCEIVER_INFO,
    TRANSCEIVER_INFO_PATTERN,
)
from sonic_exporter.converters import boolify, floatify, get_uptime, to_timestamp

try:
    import swsssdk
except ImportError:
    import sonic_exporter.test.mock_db as swsssdk
import os
import subprocess
import sys
import logging
from sonic_exporter.custom_metric_types import CustomCounter
import logging.handlers


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

    rx_power_regex = re.compile(r"^rx(\d*)power$")
    tx_power_regex = re.compile(r"^tx(\d*)power$")
    tx_bias_regex = re.compile(r"^tx(\d*)bias$")
    fan_slot_regex = re.compile(r"^((?:PSU|Fantray).*?\d+).*?(?!FAN|_).*?(\d+)$")

    @staticmethod
    def get_counter_key(name: str) -> str:
        return f"{COUNTER_TABLE_PREFIX}{name}"

    @staticmethod
    def get_port_table_key(name: str) -> str:
        if name.startswith("PortChannel"):
            raise ValueError(f"{name} is not a physical interface")
        return f"{PORT_TABLE_PREFIX}{name}"

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
        self.sonic_db.connect(self.sonic_db.APPL_DB)
        self.sonic_db.connect(self.sonic_db.CONFIG_DB)
        self.curr_time = time.time()
        self._init_metrics()

    def _init_metrics(self):
        # at start of server get counters data and negate it with current data while exporting
        # Interface counters
        interface_labels = ["interface"]
        self.metric_interface_info = prom.Gauge(
            "sonic_interface_info",
            "Interface Information (Description, MTU, Speed)",
            interface_labels + ["description", "mtu", "speed"],
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
        ## Interface Status Gauges
        self.metric_interface_operational_status = prom.Gauge(
            "sonic_interface_operational_status",
            "The Operational Status reported from the Device (0(DOWN)/1(UP))",
            interface_labels,
        )

        self.metric_interface_admin_status = prom.Gauge(
            "sonic_interface_admin_status",
            "The Configuration Status reported from the Device (0(DOWN)/1(UP))",
            interface_labels,
        )
        self.metric_interface_last_flapped_seconds = prom.Gauge(
            "sonic_interface_last_flapped_seconds",
            "The Timestamp as Unix Timestamp since the last flap of the interface.",
            interface_labels,
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
        ## Optic Health Information
        self.metric_interface_receive_optic_power_dbm = prom.Gauge(
            "sonic_interface_receive_optic_power_dbm",
            "Power value for all the interfaces",
            interface_labels + ["optic_unit"],
        )
        self.metric_interface_transmit_optic_power_dbm = prom.Gauge(
            "sonic_interface_transmit_optic_power_dbm",
            "Power value for all the interfaces",
            interface_labels + ["optic_unit"],
        )
        self.metric_interface_transmit_optic_bias_amperes = prom.Gauge(
            "sonic_interface_transmit_optic_bias_amperes",
            "Transmit Bias Current for all optics in the interface",
            interface_labels + ["optic_unit"],
        )
        self.metric_interface_optic_celsius = prom.Gauge(
            "sonic_interface_optic_celsius",
            "Temperature for all interfaces",
            interface_labels,
        )
        self.metric_interface_optic_volts = prom.Gauge(
            "sonic_interface_optic_volts",
            "Voltage of all transceiver optics per interface",
            interface_labels,
        )
        self.metric_interface_threshold_optic_volts = prom.Gauge(
            "sonic_interface_threshold_optic_volts",
            "Thresholds for the Voltage of the transceivers (high_alarm, high_warning, low_alarm, low_warning)",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_optic_celsius = prom.Gauge(
            "sonic_interface_threshold_optic_celsius",
            "Thresholds for the Temperatures of the transceivers (high_alarm, high_warning, low_alarm, low_warning)",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_receive_optic_power_dbm = prom.Gauge(
            "sonic_interface_threshold_receive_optic_power_dbm",
            "Thresholds for the power on receiving end of the transceivers (high_alarm, high_warning, low_alarm, low_warning)",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_transmit_optic_power_dbm = prom.Gauge(
            "sonic_interface_threshold_transmit_optic_power_dbm",
            "Thresholds for the power on transmit end of the transceivers (high_alarm, high_warning, low_alarm, low_warning)",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_transmit_optic_bias_amperes = prom.Gauge(
            "sonic_interface_threshold_transmit_optic_bias_amperes",
            "Thresholds for the power on transmit bias current end of the transceivers (high_alarm, high_warning, low_alarm, low_warning)",
            interface_labels + ["alarm_type"],
        )
        ## Transceiver Info
        self.metric_interface_transceiver_info = prom.Gauge(
            "sonic_interface_transceiver_info",
            "General Information about the transceivers per Interface",
            interface_labels
            + [
                "serial",
                "part_number",
                "revision",
                "formfactor",
                "connector_type",
                "display_name",
                "media_interface",
            ],
        )
        self.metric_interface_cable_length_meters = prom.Gauge(
            "sonic_interface_cable_length_meters",
            "The length of the plugged in Cable",
            interface_labels + ["cable_type", "connector_type"],
        )
        ## PSU Info
        self.metric_device_psu_input_volts = prom.Gauge(
            "sonic_device_psu_input_volts",
            "The Amount of Voltage provided to the power supply",
            ["slot"],
        )
        self.metric_device_psu_input_amperes = prom.Gauge(
            "sonic_device_psu_input_amperes",
            "The Amount of Amperes provided to the power supply",
            ["slot"],
        )
        self.metric_device_psu_output_volts = prom.Gauge(
            "sonic_device_psu_output_volts",
            "The Amount of Voltage provided to the internal system",
            ["slot"],
        )
        self.metric_device_psu_output_amperes = prom.Gauge(
            "sonic_device_psu_output_amperes",
            "The Amount of Amperes used by the system",
            ["slot"],
        )
        self.metric_device_psu_operational_status = prom.Gauge(
            "sonic_device_psu_operational_status",
            "Shows if a power supply is Operational (0(DOWN)/1(UP))",
            ["slot"],
        )
        self.metric_device_psu_available_status = prom.Gauge(
            "sonic_device_psu_available_status",
            "Shows if a power supply is plugged in (0(DOWN)/1(UP))",
            ["slot"],
        )
        self.metric_device_psu_celsius = prom.Gauge(
            "sonic_device_psu_celsius",
            "The Temperature in Celsius of the PSU",
            ["slot"],
        )
        self.metric_device_psu_info = prom.Gauge(
            "sonic_device_psu_info",
            "More information of the psu",
            ["slot", "serial", "model_name", "model"],
        )
        ## FAN Info
        self.metric_device_fan_rpm = prom.Gauge(
            "sonic_device_fan_rpm", "The Rounds per minute of the fan", ["name", "slot"]
        )
        self.metric_device_fan_operational_status = prom.Gauge(
            "sonic_device_fan_operational_status",
            "Shows if a fan is Operational (0(DOWN)/1(UP))",
            ["name", "slot"],
        )
        self.metric_device_fan_available_status = prom.Gauge(
            "sonic_device_fan_available_status",
            "Shows if a fan is plugged in (0(DOWN)/1(UP))",
            ["name", "slot"],
        )
        ## Temp Info
        self.metric_device_sensor_celsius = prom.Gauge(
            "sonic_device_sensor_celsius",
            "Show the temperature of the Sensors in the switch",
            ["name"],
        )
        self.metric_device_threshold_sensor_celsius = prom.Gauge(
            "sonic_device_sensor_threshold_celsius",
            "Thresholds for the temperature sensors (high_alarm, high_warning, low_alarm, low_warning)",
            ["name"] + ["alarm_type"],
        )
        ## System Info
        self.system_uptime = prom.Gauge(
            "sonic_device_uptime_seconds", "The uptime of the device in seconds"
        )
        self.system_info = prom.Info(
            "sonic_device_info",
            "part name, serial number, MAC address and software vesion of the System",
        )
        self.system_memory_ratio = prom.Gauge(
            "sonic_device_memory_ratio", "Memory Usage of the device in percentage 0-1"
        )
        self.system_cpu_ratio = prom.Gauge(
            "sonic_device_cpu_ratio", "CPU Usage of the device in percentage 0-1"
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
            return _decode(self.sonic_db.get(self.sonic_db.CONFIG_DB, key, sub_key))
        except (ValueError, KeyError):
            return ""

    def get_additional_info(self, ifname):
        return self.get_portinfo(ifname, "alias") or ifname

    def export_interface_counter(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        for ifname in maps:
            counter_key = Export.get_counter_key(_decode(maps[ifname]))
            ifname_decoded = _decode(ifname)
            if ifname_decoded.lower() in COUNTER_IGNORE:
                continue
            self.metric_interface_info.labels(
                self.get_additional_info(ifname),
                self.get_portinfo(ifname, "description"),
                self.get_portinfo(ifname, "mtu"),
                f"{'{}Gbps'.format(int(round(int(self.get_portinfo(ifname, 'speed'))) / 1000)) if self.get_portinfo(ifname, 'speed') else ''}",
            ).set(1)
            ## Ethernet RX
            for size, key in zip(
                (64, 127, 255, 511, 1023, 1518, 2047, 4095, 9216, 16383),
                (
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
                ),
            ):
                self.metric_interface_received_ethernet_packets.labels(
                    self.get_additional_info(ifname), size
                ).set(
                    floatify(
                        _decode(
                            self.sonic_db.get(
                                self.sonic_db.COUNTERS_DB, counter_key, key
                            )
                        )
                    )
                )
            ## Ethernet TX
            for size, key in zip(
                (64, 127, 255, 511, 1023, 1518, 2047, 4095, 9216, 16383),
                (
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
                ),
            ):
                self.metric_interface_transmitted_ethernet_packets.labels(
                    self.get_additional_info(ifname), size
                ).set(
                    floatify(
                        _decode(
                            self.sonic_db.get(
                                self.sonic_db.COUNTERS_DB, counter_key, key
                            )
                        )
                    )
                )
            ## RX
            self.metric_interface_received_bytes.labels(
                self.get_additional_info(ifname)
            ).set(
                floatify(
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
                floatify(
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
                floatify(
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
                floatify(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS",
                    )
                )
            )

            ## RX Errors
            self.metric_interface_receive_error_input_packets.labels(
                self.get_additional_info(ifname), "error"
            ).set(
                floatify(
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
                floatify(
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
                floatify(
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
                floatify(
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
                floatify(
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
                floatify(
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
                floatify(
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
                floatify(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS",
                    )
                )
            )
            # SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS
            ## TX Errors
            self.metric_interface_transmit_error_output_packets.labels(
                self.get_additional_info(ifname), "error"
            ).set(
                floatify(
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
                floatify(
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
                floatify(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_TX_PKTS",
                    )
                )
            )
            logging.debug("export_intf_counter : ifname={}".format(ifname))
            try:
                port_table_key = Export.get_port_table_key(ifname)
                is_operational = _decode(
                    self.sonic_db.get(
                        self.sonic_db.APPL_DB, port_table_key, "oper_status"
                    )
                )
                converters.get
                last_flapped_seconds = to_timestamp(
                    floatify(
                        _decode(
                            self.sonic_db.get(
                                self.sonic_db.APPL_DB,
                                port_table_key,
                                "oper_status_change_uptime",
                            )
                        )
                    )
                )
                is_admin = self.get_portinfo(ifname, "admin_status")
                self.metric_interface_operational_status.labels(
                    self.get_additional_info(ifname)
                ).set(boolify(is_operational))
                self.metric_interface_admin_status.labels(
                    self.get_additional_info(ifname)
                ).set(boolify(is_admin))
                self.metric_interface_last_flapped_seconds.labels(
                    self.get_additional_info(ifname)
                ).set(floatify(last_flapped_seconds))
            except ValueError:
                pass

    def export_interface_queue_counters(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            decoded_counter_key = _decode(maps[ifname])
            counter_key = Export.get_counter_key(decoded_counter_key)
            packet_type = _decode(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    COUNTER_QUEUE_TYPE_MAP,
                    decoded_counter_key,
                )
            )
            ifname = _decode(ifname)
            packets = self.sonic_db.get(
                self.sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_PACKETS",
            )
            bytes = self.sonic_db.get(
                self.sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_BYTES",
            )
            queue_type = "N/A"
            ifname, queue = ifname.split(":")
            if ifname.lower() in COUNTER_IGNORE:
                continue
            if packet_type.endswith("MULTICAST"):
                queue_type = "multicast"
            if packet_type.endswith("UNICAST"):
                queue_type = "unicast"
            logging.debug(
                "export_intf_queue_counters : ifname={}, queue_type={}, packets={}".format(
                    ifname, queue_type, packets
                )
            )
            logging.debug(
                "export_intf_queue_counters : ifname={}, queue_type={}, bytes={}".format(
                    ifname, queue_type, bytes
                )
            )
            self.metric_interface_queue_processed_packets.labels(
                self.get_additional_info(ifname), queue, queue_type
            ).set(packets)
            self.metric_interface_queue_processed_bytes.labels(
                self.get_additional_info(ifname), queue, queue_type
            ).set(bytes)

    def export_interface_optic_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern=TRANSCEIVER_DOM_SENSOR_PATTERN
        )
        logging.debug("export_interface_optic_data : keys={}".format(keys))
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_DOM_SENSOR, "")
            transceiver_sensor_data = self.sonic_db.get_all(self.sonic_db.STATE_DB, key)
            for measure in transceiver_sensor_data:
                measure_dec = _decode(measure)
                try:
                    value = transceiver_sensor_data[measure]
                    if floatify(value):
                        match measure_dec:
                            case "voltage":
                                self.metric_interface_optic_volts.labels(
                                    self.get_additional_info(ifname)
                                ).set(floatify(value))
                            case "vcchighalarm":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname), "high_alarm"
                                ).set(floatify(value))
                            case "vcchighwarning":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname), "high_warning"
                                ).set(floatify(value))
                            case "vcclowalarm":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname), "low_alarm"
                                ).set(floatify(value))
                            case "vcclowwarning":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname), "low_warning"
                                ).set(floatify(value))
                            case "temperature":
                                self.metric_interface_optic_celsius.labels(
                                    self.get_additional_info(ifname)
                                ).set(floatify(value))
                            case "temphighalarm":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname), "high_alarm"
                                ).set(floatify(value))
                            case "temphighwarning":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname), "high_warning"
                                ).set(floatify(value))
                            case "templowalarm":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname), "low_alarm"
                                ).set(floatify(value))
                            case "templowwarning":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname), "low_warning"
                                ).set(floatify(value))
                            case "txbiashighalarm":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname), "high_alarm"
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txbiashighwarning":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname), "high_warning"
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txbiaslowalarm":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname), "low_alarm"
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txbiaslowwarning":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname), "low_warning"
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txpowerhighalarm":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "high_alarm"
                                ).set(
                                    floatify(value)
                                )
                            case "txpowerhighwarning":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "high_warning"
                                ).set(
                                    floatify(value)
                                )
                            case "txpowerlowalarm":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "low_alarm"
                                ).set(
                                    floatify(value)
                                )
                            case "txpowerlowwarning":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "low_warning"
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerhighalarm":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "high_alarm"
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerhighwarning":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "high_warning"
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerlowalarm":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "low_alarm"
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerlowwarning":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname), "low_warning"
                                ).set(
                                    floatify(value)
                                )
                            case _:
                                if match := self.rx_power_regex.fullmatch(measure_dec):
                                    optic_unit = match.group(1)
                                    self.metric_interface_receive_optic_power_dbm.labels(
                                        self.get_additional_info(ifname), optic_unit
                                    ).set(
                                        floatify(value)
                                    )
                                elif match := self.tx_power_regex.fullmatch(
                                    measure_dec
                                ):
                                    optic_unit = match.group(1)
                                    self.metric_interface_transmit_optic_power_dbm.labels(
                                        self.get_additional_info(ifname), optic_unit
                                    ).set(
                                        floatify(value)
                                    )
                                elif match := self.tx_bias_regex.fullmatch(measure_dec):
                                    optic_unit = match.group(1)
                                    # This resolves mA to Amperes
                                    self.metric_interface_transmit_optic_bias_amperes.labels(
                                        self.get_additional_info(ifname), optic_unit
                                    ).set(
                                        floatify(value) / 1000
                                    )
                except ValueError:
                    pass

    def export_interface_cable_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern=TRANSCEIVER_INFO_PATTERN
        )
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_INFO, "")
            cable_type = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "Connector")
            )
            connector_type = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "connector_type")
            ).lower()
            serial = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "vendor_serial_number")
            )
            part_number = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "vendor_part_number")
            )
            revision = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "vendor_revision")
            )
            form_factor = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "form_factor")
            ).lower()
            display_name = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "display_name")
            )
            media_interface = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "media_interface")
            ).lower()
            try:
                cable_len = floatify(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "cable_length")
                )
                self.metric_interface_cable_length_meters.labels(
                    self.get_additional_info(ifname), cable_type, connector_type
                ).set(cable_len)
            except ValueError:
                pass
            logging.debug(
                f"export_interface_cable_data : interface={self.get_additional_info(ifname)}"
            )
            self.metric_interface_transceiver_info.labels(
                self.get_additional_info(ifname),
                serial,
                part_number,
                revision,
                form_factor,
                connector_type,
                display_name,
                media_interface,
            ).set(1)

    def export_psu_info(self):
        keys = self.sonic_db.keys(self.sonic_db.STATE_DB, pattern=PSU_INFO_PATTERN)
        for key in keys:
            serial = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "serial"))
            available_status = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "presence")
            )
            operational_status = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "status")
            )
            model = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "model"))
            model_name = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "name"))
            _, slot = _decode(key.replace(PSU_INFO, "")).lower().split(" ")
            try:
                in_volts = floatify(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "input_voltage")
                )
                in_amperes = floatify(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "input_current")
                )
                self.metric_device_psu_input_amperes.labels(slot).set(in_amperes)
                self.metric_device_psu_input_volts.labels(slot).set(in_volts)
                logging.debug(
                    f"export_psu_info : slot={slot}, in_amperes={in_amperes}, in_volts={in_volts}"
                )
            except ValueError:
                pass
            try:
                out_volts = floatify(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "output_voltage")
                )
                out_amperes = floatify(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "output_current")
                )
                self.metric_device_psu_output_amperes.labels(slot).set(out_amperes)
                self.metric_device_psu_output_volts.labels(slot).set(out_volts)
                logging.debug(
                    f"export_psu_info : slot={slot}, out_amperes={out_amperes}, out_volts={out_volts}"
                )
            except ValueError:
                pass
            try:
                temperature = floatify(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "temperature")
                )
                self.metric_device_psu_celsius.labels(slot).set(temperature)
            except ValueError:
                pass
            self.metric_device_psu_available_status.labels(slot).set(
                boolify(available_status)
            )
            self.metric_device_psu_operational_status.labels(slot).set(
                boolify(operational_status)
            )
            self.metric_device_psu_info.labels(slot, serial, model_name, model).set(1)

    def export_fan_info(self):
        keys = self.sonic_db.keys(self.sonic_db.STATE_DB, pattern=FAN_INFO_PATTERN)
        for key in keys:
            try:
                fullname = _decode(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "name")
                )
                rpm = floatify(self.sonic_db.get(self.sonic_db.STATE_DB, key, "speed"))
                is_operational = boolify(
                    _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "status"))
                )
                is_available = boolify(
                    _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "presence"))
                )
                name = fullname
                slot = "0"
                if match := self.fan_slot_regex.fullmatch(fullname):
                    name = match.group(1)
                    slot = match.group(2)
                    # This handles the special case of the AS7326 which bounds health of the PSU Fan to the Health of the Power Supply
                    if not is_operational and fullname.lower().startswith("psu"):
                        is_operational = boolify(
                            _decode(
                                self.sonic_db.get(
                                    self.sonic_db.STATE_DB,
                                    f"{PSU_INFO}{name}",
                                    "status",
                                )
                            )
                        )
                self.metric_device_fan_rpm.labels(name, slot).set(rpm)
                self.metric_device_fan_operational_status.labels(name, slot).set(
                    is_operational
                )
                self.metric_device_fan_available_status.labels(name, slot).set(
                    is_available
                )
                logging.debug(
                    f"export_fan_info : fullname={fullname} oper={is_operational}, presence={is_available}, rpm={rpm}"
                )
            except ValueError:
                pass

    def export_temp_info(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern=TEMPERATURE_INFO_PATTERN
        )
        for key in keys:
            try:
                name = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "name"))
                temp = floatify(
                    _decode(
                        self.sonic_db.get(self.sonic_db.STATE_DB, key, "temperature")
                    )
                )
                high_threshold = floatify(
                    _decode(
                        self.sonic_db.get(self.sonic_db.STATE_DB, key, "high_threshold")
                    )
                )
                self.metric_device_sensor_celsius.labels(name).set(temp)
                self.metric_device_threshold_sensor_celsius.labels(
                    name, "high_alarm"
                ).set(high_threshold)
                logging.debug(
                    f"export_temp_info : name={name}, temp={temp}, high_threshold={high_threshold}"
                )
            except ValueError:
                pass

    def export_system_info(self):
        part_num = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x22", "Value")
        )
        serial_num = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x23", "Value")
        )
        mac_addr = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x24", "Value")
        )
        onie_version = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x29", "Value")
        )
        software_version = self.sonic_db.get(
            self.sonic_db.STATE_DB, "IMAGE_GLOBAL|config", "current"
        )
        self.system_uptime.set(get_uptime().total_seconds())
        self.system_info.info(
            {
                "part_number": part_num,
                "serial_number": serial_num,
                "mac_address": mac_addr,
                "software_version": software_version,
                "onie_version": onie_version,
            }
        )
        logging.debug(
            "export_sys_info : part_num={}, serial_num={}, mac_addr={}, software_version={}".format(
                part_num, serial_num, mac_addr, software_version
            )
        )
        keys = self.sonic_db.keys(self.sonic_db.STATE_DB, pattern=PROCESS_STATS_PATTERN)
        cpu_memory_usages = [
            (
                floatify(
                    _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "%CPU"))
                ),
                floatify(
                    _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "%MEM"))
                ),
            )
            for key in keys
            if not key.lower().endswith("lastupdatetime")
        ]
        cpu_usage = sum(cpu_usage for cpu_usage, _ in cpu_memory_usages)
        memory_usage = sum(memory_usage for _, memory_usage in cpu_memory_usages)
        self.system_cpu_ratio.set(cpu_usage / 100)
        self.system_memory_ratio.set(memory_usage / 100)

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
                    _ = floatify(cmd_out[bgp_neighbour]["bgpTimerUp"])
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

    def start_export(self):
        try:
            self.export_interface_counter()
            self.export_interface_queue_counters()
            self.export_interface_cable_data()
            self.export_interface_optic_data()
            self.export_system_info()
            self.export_psu_info()
            self.export_fan_info()
            self.export_temp_info()
            # self.export_bgp_peer_status()
            # self.export_bgp_num_routes()
            # self.export_system_top10_process()
        except KeyboardInterrupt as e:
            raise e


def main():
    data_extract_interval = floatify(
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
