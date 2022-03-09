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
import ipaddress
import logging
import logging.handlers
import os
import re
import socket
import sys
import time

import prometheus_client as prom

from sonic_exporter.constants import (
    CHASSIS_INFO,
    CHASSIS_INFO_PATTERN,
    COUNTER_IGNORE,
    COUNTER_PORT_MAP,
    COUNTER_QUEUE_MAP,
    COUNTER_QUEUE_TYPE_MAP,
    COUNTER_TABLE_PREFIX,
    FAN_INFO_PATTERN,
    PORT_TABLE_PREFIX,
    PROCESS_STATS,
    PROCESS_STATS_IGNORE,
    PROCESS_STATS_PATTERN,
    PSU_INFO,
    PSU_INFO_PATTERN,
    SAG,
    SAG_GLOBAL,
    SAG_PATTERN,
    TEMP_SENSORS,
    TEMPERATURE_INFO_PATTERN,
    TRANSCEIVER_DOM_SENSOR,
    TRANSCEIVER_DOM_SENSOR_PATTERN,
    TRANSCEIVER_INFO,
    TRANSCEIVER_INFO_PATTERN,
    TRUE_VALUES,
    VLAN_INTERFACE,
    VXLAN_TUNNEL_MAP_PATTERN,
    VXLAN_TUNNEL_TABLE,
    VXLAN_TUNNEL_TABLE_PATTERN,
)
from sonic_exporter.converters import boolify
from sonic_exporter.converters import decode as _decode
from sonic_exporter.converters import floatify, get_uptime, to_timestamp
from sonic_exporter.custom_metric_types import CustomCounter
from sonic_exporter.enums import (
    AddressFamily,
    AirFlow,
    InternetProtocol,
    OSILayer,
    AlarmType,
    SwitchModel,
)
from sonic_exporter.utilities import timed_cache

level = os.environ.get("SONIC_EXPORTER_LOGLEVEL", "INFO")
logging.basicConfig(
    encoding="utf-8",
    stream=sys.stdout,
    format="[%(asctime)s][%(levelname)s][%(name)s] %(message)s",
    level=logging.getLevelName(level),
)


class Export:

    rx_power_regex = re.compile(r"^rx(\d*)power$")
    tx_power_regex = re.compile(r"^tx(\d*)power$")
    tx_bias_regex = re.compile(r"^tx(\d*)bias$")
    fan_slot_regex = re.compile(r"^((?:PSU|Fantray).*?\d+).*?(?!FAN|_).*?(\d+)$")
    chassis_slot_regex = re.compile(r"^.*?(\d+)$")

    @staticmethod
    def get_counter_key(name: str) -> str:
        return f"{COUNTER_TABLE_PREFIX}{name}"

    @staticmethod
    def get_port_table_key(name: str) -> str:
        if name.startswith("PortChannel"):
            raise ValueError(f"{name} is not a physical interface")
        return f"{PORT_TABLE_PREFIX}{name}"

    @staticmethod
    @timed_cache(seconds=600)
    def dns_lookup(ip: str) -> str:
        if ip is None:
            return ""
        try:
            ipaddress.ip_address(ip)
            return socket.gethostbyaddr(ip)[0]
        except (ValueError, socket.herror):
            return ip

    def __init__(self, developer_mode: bool):
        if developer_mode:
            import sonic_exporter.test.mock_db as mock_db
            from sonic_exporter.test.mock_sys_class_hwmon import MockSystemClassHWMon
            from sonic_exporter.test.mock_sys_class_net import (
                MockSystemClassNetworkInfo,
            )
            from sonic_exporter.test.mock_vtysh import MockVtySH

            self.vtysh = MockVtySH()
            self.sys_class_net = MockSystemClassNetworkInfo()
            self.sys_class_hwmon = MockSystemClassHWMon()
            self.sonic_db = mock_db.SonicV2Connector(password="")
        else:
            import swsssdk

            from sonic_exporter.sys_class_net import SystemClassNetworkInfo
            from sonic_exporter.sys_class_hwmon import SystemClassHWMon
            from sonic_exporter.vtysh import VtySH

            self.vtysh = VtySH()
            self.sys_class_net = SystemClassNetworkInfo()
            self.sys_class_hwmon = SystemClassHWMon()
            try:
                secret = os.environ["REDIS_AUTH"]
                logging.debug(f"Password from ENV: {secret}")
            except KeyError:
                logging.error("Password ENV REDIS_AUTH is not set ... Exiting")
                sys.exit(1)
            self.sonic_db = swsssdk.SonicV2Connector(password=secret)

        self.sonic_db.connect(self.sonic_db.COUNTERS_DB)
        self.sonic_db.connect(self.sonic_db.STATE_DB)
        self.sonic_db.connect(self.sonic_db.APPL_DB)
        self.sonic_db.connect(self.sonic_db.CONFIG_DB)
        self._init_metrics()
        self.chassis = {
            _decode(key).replace(CHASSIS_INFO, ""): self.sonic_db.get_all(
                self.sonic_db.STATE_DB, key
            )
            for key in self.sonic_db.keys(
                self.sonic_db.STATE_DB, pattern=CHASSIS_INFO_PATTERN
            )
        }
        self.platform_name: str = list(
            set(
                _decode(chassis.get("platform_name", ""))
                for chassis in self.chassis.values()
            )
        )[0].strip()
        self.product_name = list(
            set(
                _decode(chassis.get("product_name", ""))
                for chassis in self.chassis.values()
            )
        )[0].strip()

    def _init_metrics(self):
        # at start of server get counters data and negate it with current data while exporting
        # Interface counters
        interface_labels = ["interface"]
        bgp_labels = [
            "vrf",
            "peer_name",
            "neighbor",
            "ip_family",
            "message_type",
            "remote_as",
        ]
        sag_labels = [
            "interface",
            "vrf",
            "gateway_ip",
            "ip_family",
            "vni",
        ]
        evpn_vni_labels = ["vni", "interface", "svi", "osi_layer", "vrf"]
        self.metric_interface_info = prom.Gauge(
            "sonic_interface_info",
            "Interface Information (Description, MTU, Speed)",
            interface_labels + ["description", "mtu", "speed", "device"],
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
            "sonic_interface_received_ethernet_packets_total",
            "Size of the Ethernet Frames received",
            interface_labels + ["packet_size"],
        )
        self.metric_interface_transmitted_ethernet_packets = CustomCounter(
            "sonic_interface_transmitted_ethernet_packets_total",
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
        self.metric_interface_last_flapped_seconds = CustomCounter(
            "sonic_interface_last_flapped_seconds_total",
            "The Timestamp as Unix Timestamp since the last flap of the interface.",
            interface_labels,
        )
        ## Queue Counters
        self.metric_interface_queue_processed_packets = CustomCounter(
            "sonic_interface_queue_processed_packets_total",
            "Interface queue counters",
            interface_labels + ["queue"] + ["delivery_mode"],
        )
        self.metric_interface_queue_processed_bytes = CustomCounter(
            "sonic_interface_queue_processed_bytes_total",
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
            f"Thresholds for the Voltage of the transceivers {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_optic_celsius = prom.Gauge(
            "sonic_interface_threshold_optic_celsius",
            f"Thresholds for the Temperatures of the transceivers {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_receive_optic_power_dbm = prom.Gauge(
            "sonic_interface_threshold_receive_optic_power_dbm",
            f"Thresholds for the power on receiving end of the transceivers {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_transmit_optic_power_dbm = prom.Gauge(
            "sonic_interface_threshold_transmit_optic_power_dbm",
            f"Thresholds for the power on transmit end of the transceivers {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            interface_labels + ["alarm_type"],
        )
        self.metric_interface_threshold_transmit_optic_bias_amperes = prom.Gauge(
            "sonic_interface_threshold_transmit_optic_bias_amperes",
            f"Thresholds for the power on transmit bias current end of the transceivers {', '.join(alarm_type.value for alarm_type in AlarmType)}",
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
            f"Thresholds for the temperature sensors {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            ["name", "alarm_type"],
        )
        ## VXLAN Tunnel Info
        self.metric_vxlan_operational_status = prom.Gauge(
            "sonic_vxlan_operational_status",
            "Reports the status of the VXLAN Tunnel to Endpoints (0(DOWN)/1(UP))",
            ["neighbor"],
        )
        ## System Info
        self.metric_device_uptime = CustomCounter(
            "sonic_device_uptime_seconds_total", "The uptime of the device in seconds"
        )
        self.metric_device_info = prom.Gauge(
            "sonic_device_info",
            "part name, serial number, MAC address and software vesion of the System",
            [
                "chassis",
                "platform_name",
                "part_number",
                "serial_number",
                "mac_address",
                "software_version",
                "onie_version",
                "hardware_revision",
                "product_name",
            ],
        )
        self.system_memory_ratio = prom.Gauge(
            "sonic_device_memory_ratio",
            "Memory Usage of the device in percentage [0-1]",
        )
        self.system_cpu_ratio = prom.Gauge(
            "sonic_device_cpu_ratio", "CPU Usage of the device in percentage [0-1]"
        )
        ## BGP Info
        self.metric_bgp_uptime_seconds = CustomCounter(
            "sonic_bgp_uptime_seconds_total",
            "Uptime of the session with the other BGP Peer",
            bgp_labels,
        )
        self.metric_bgp_status = prom.Gauge(
            "sonic_bgp_status",
            "The Session Status to the other BGP Peer",
            bgp_labels,
        )
        self.metric_bgp_prefixes_received = CustomCounter(
            "sonic_bgp_prefixes_received_total",
            "The Prefixes Received from the other peer.",
            bgp_labels,
        )
        self.metric_bgp_prefixes_transmitted = CustomCounter(
            "sonic_bgp_prefixes_transmitted_total",
            "The Prefixes Transmitted to the other peer.",
            bgp_labels,
        )
        self.metric_bgp_messages_received = CustomCounter(
            "sonic_bgp_messages_received_total",
            "The messages Received from the other peer.",
            bgp_labels,
        )
        self.metric_bgp_messages_transmitted = CustomCounter(
            "sonic_bgp_messages_transmitted_total",
            "The messages Transmitted to the other peer.",
            bgp_labels,
        )
        ## Static Anycast Gateway
        self.metric_sag_operational_status = prom.Gauge(
            "sonic_sag_operational_status",
            "Reports the operational status of the Static Anycast Gateway (0(DOWN)/1(UP))",
            sag_labels,
        )
        self.metric_sag_admin_status = prom.Gauge(
            "sonic_sag_admin_status",
            "Reports the admin status of the Static Anycast Gateway (0(DOWN)/1(UP))",
            sag_labels,
        )
        self.metric_sag_info = prom.Gauge(
            "sonic_sag_info",
            "Static Anycast Gateway General Information",
            ["ip_family", "mac_address"],
        )
        ## EVPN Information
        self.metric_evpn_status = prom.Gauge(
            "sonic_evpn_status", "The Status of the EVPN Endpoints", evpn_vni_labels
        )
        self.metric_evpn_remote_vteps = prom.Gauge(
            "sonic_evpn_remote_vteps",
            "The number of remote VTEPs associated with that VNI",
            evpn_vni_labels,
        )

        self.metric_evpn_l2_vnis = prom.Gauge(
            "sonic_evpn_l2_vnis",
            "The number of l2 vnis associated with an l3 VNI",
            evpn_vni_labels,
        )
        self.metric_evpn_mac_addresses = prom.Gauge(
            "sonic_evpn_mac_addresses",
            "The number of Mac Addresses learned VNI",
            evpn_vni_labels,
        )
        self.metric_evpn_arps = prom.Gauge(
            "sonic_evpn_arps", "The number of ARPs cached for the VNI", evpn_vni_labels
        )

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

    def export_vxlan_tunnel_info(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern=VXLAN_TUNNEL_TABLE_PATTERN
        )
        if not keys:
            return
        for key in keys:
            try:
                neighbor = ""
                _, neighbor = tuple(key.replace(VXLAN_TUNNEL_TABLE, "").split("_"))
                is_operational = boolify(
                    _decode(
                        self.sonic_db.get(self.sonic_db.STATE_DB, key, "operstatus")
                    )
                )
                self.metric_vxlan_operational_status.labels(
                    self.dns_lookup(neighbor)
                ).set(is_operational)
                logging.debug(
                    f"export_vxlan_tunnel : neighbor={neighbor}, is_operational={is_operational}"
                )
            except ValueError as e:
                pass

    def export_interface_counters(self):
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
                ifname,
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
        if not keys:
            return
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
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_ALARM.value,
                                ).set(floatify(value))
                            case "vcchighwarning":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_WARNING.value,
                                ).set(floatify(value))
                            case "vcclowalarm":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_ALARM.value,
                                ).set(floatify(value))
                            case "vcclowwarning":
                                self.metric_interface_threshold_optic_volts.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_WARNING.value,
                                ).set(floatify(value))
                            case "temperature":
                                self.metric_interface_optic_celsius.labels(
                                    self.get_additional_info(ifname)
                                ).set(floatify(value))
                            case "temphighalarm":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_ALARM.value,
                                ).set(floatify(value))
                            case "temphighwarning":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_WARNING.value,
                                ).set(floatify(value))
                            case "templowalarm":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_ALARM.value,
                                ).set(floatify(value))
                            case "templowwarning":
                                self.metric_interface_threshold_optic_celsius.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_WARNING.value,
                                ).set(floatify(value))
                            case "txbiashighalarm":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_ALARM.value,
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txbiashighwarning":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_WARNING.value,
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txbiaslowalarm":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_ALARM.value,
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txbiaslowwarning":
                                self.metric_interface_threshold_transmit_optic_bias_amperes.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_WARNING.value,
                                ).set(
                                    floatify(value) / 1000
                                )
                            case "txpowerhighalarm":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_ALARM.value,
                                ).set(
                                    floatify(value)
                                )
                            case "txpowerhighwarning":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_WARNING.value,
                                ).set(
                                    floatify(value)
                                )
                            case "txpowerlowalarm":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_ALARM.value,
                                ).set(
                                    floatify(value)
                                )
                            case "txpowerlowwarning":
                                self.metric_interface_threshold_transmit_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_WARNING.value,
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerhighalarm":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_ALARM.value,
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerhighwarning":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.HIGH_WARNING.value,
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerlowalarm":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_ALARM.value,
                                ).set(
                                    floatify(value)
                                )
                            case "rxpowerlowwarning":
                                self.metric_interface_threshold_receive_optic_power_dbm.labels(
                                    self.get_additional_info(ifname),
                                    AlarmType.LOW_WARNING.value,
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
        if not keys:
            return
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_INFO, "")
            cable_type = _decode(
                str(self.sonic_db.get(self.sonic_db.STATE_DB, key, "Connector")).lower()
            )
            connector_type = _decode(
                str(self.sonic_db.get(self.sonic_db.STATE_DB, key, "connector_type"))
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
        if not keys:
            return
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
        if not keys:
            return
        for key in keys:
            try:
                fullname = _decode(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "name")
                )
                rpm = floatify(self.sonic_db.get(self.sonic_db.STATE_DB, key, "speed"))
                is_operational = _decode(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "status")
                )
                is_available = boolify(
                    _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "presence"))
                )
                name = fullname
                slot = "0"
                if match := self.fan_slot_regex.fullmatch(fullname):
                    name = match.group(1).rstrip()
                    slot = match.group(2).strip()
                    # This handles the special case of the AS7326 which bounds health of the PSU Fan to the Health of the Power Supply
                    if is_operational is None and fullname.lower().startswith("psu"):
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
                    boolify(is_operational)
                )
                self.metric_device_fan_available_status.labels(name, slot).set(
                    is_available
                )
                logging.debug(
                    f"export_fan_info : fullname={fullname} oper={boolify(is_operational)}, presence={is_available}, rpm={rpm}"
                )
            except ValueError:
                pass

    def export_hwmon_temp_info(self, switch_model, air_flow):
        for name, sensor in self.sys_class_hwmon.sensors.items():
            try:
                last_two_bytes = sensor.address[-2:]
                name = TEMP_SENSORS[switch_model][air_flow][last_two_bytes]
            except (ValueError, KeyError, TypeError):
                continue
            for value in sensor.values:
                _, subvalue = value.name.split("_", maxsplit=1)
                logging.debug(
                    f"export_hwmon_temp_info :: name={name}, -> value={value}"
                )
                match subvalue:
                    case "max":
                        self.metric_device_threshold_sensor_celsius.labels(
                            name, AlarmType.HIGH_ALARM.value
                        ).set(value.value)
                    case "max_hyst":
                        self.metric_device_threshold_sensor_celsius.labels(
                            name, AlarmType.HIGH_WARNING.value
                        ).set(value.value)
                    case "input":
                        self.metric_device_sensor_celsius.labels(name).set(value.value)

    def export_temp_info(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern=TEMPERATURE_INFO_PATTERN
        )
        need_additional_temp_info = False
        unknown_switch_model = False
        air_flow = None
        switch_model = None
        try:
            air_flow = AirFlow(self.product_name[-1])
            switch_model = SwitchModel(self.platform_name)
            if not keys:
                self.export_hwmon_temp_info(switch_model, air_flow)
                return
        except ValueError:
            unknown_switch_model = True
            pass
        # implement a skip on state db if keys are empty
        # Still try to get data from HWMon.
        for key in keys:
            try:
                name = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "name"))
                if name.lower().startswith("temp"):
                    need_additional_temp_info = True

                last_two_bytes: str = name[-2:]
                if not unknown_switch_model:
                    name = TEMP_SENSORS[switch_model][air_flow].get(
                        last_two_bytes, name
                    )
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
                    name, AlarmType.HIGH_ALARM.value
                ).set(high_threshold)
                logging.debug(
                    f"export_temp_info : name={name}, temp={temp}, high_threshold={high_threshold}"
                )
            except ValueError:
                pass
            if need_additional_temp_info and not unknown_switch_model:
                self.export_hwmon_temp_info(switch_model, air_flow)

    def export_system_info(self):
        self.metric_device_uptime.set(get_uptime().total_seconds())
        for chassis_raw, data in self.chassis.items():
            chassis = chassis_raw
            if match := self.chassis_slot_regex.fullmatch(chassis_raw):
                chassis = match.group(1)
            part_number = _decode(data.get("part_num", ""))
            serial_number = _decode(data.get("serial_num", ""))
            mac_address = _decode(data.get("base_mac_addr", ""))
            onie_version = _decode(data.get("onie_version", ""))
            software_version = _decode(
                self.sonic_db.get(
                    self.sonic_db.STATE_DB, "IMAGE_GLOBAL|config", "current"
                )
            )
            platform_name = _decode(data.get("platform_name", ""))
            hardware_revision = _decode(data.get("hardware_revision", ""))
            product_name = _decode(data.get("product_name", ""))
            self.metric_device_info.labels(
                chassis,
                platform_name,
                part_number,
                serial_number,
                mac_address,
                software_version,
                onie_version,
                hardware_revision,
                product_name,
            ).set(1)
            logging.debug(
                "export_sys_info : part_num={}, serial_num={}, mac_addr={}, software_version={}".format(
                    part_number, serial_number, mac_address, software_version
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
            if not key.replace(PROCESS_STATS, "").lower() in PROCESS_STATS_IGNORE
        ]
        cpu_usage = sum(cpu_usage for cpu_usage, _ in cpu_memory_usages)
        memory_usage = sum(memory_usage for _, memory_usage in cpu_memory_usages)
        self.system_cpu_ratio.set(cpu_usage / 100)
        self.system_memory_ratio.set(memory_usage / 100)
        logging.debug(
            f"export_sys_info : cpu_usage={cpu_usage}, memory_usage={memory_usage}"
        )

    def export_static_anycast_gateway_info(self):
        ## SAG Static Anycast Gateway
        ## Labels
        # gwip
        # VRF
        # VNI
        # interface
        ## Metrics
        # admin_status /sys/class/net/<interface_name>/flags
        # oper_status /sys/class/net/<interface_name>/carrier

        exportable = {InternetProtocol.v4: False, InternetProtocol.v6: False}
        keys = self.sonic_db.keys(self.sonic_db.CONFIG_DB, pattern=SAG_PATTERN)
        global_data = self.sonic_db.get_all(self.sonic_db.CONFIG_DB, SAG_GLOBAL)
        vxlan_tunnel_map = self.sonic_db.keys(
            self.sonic_db.CONFIG_DB, pattern=VXLAN_TUNNEL_MAP_PATTERN
        )

        for internet_protocol in InternetProtocol:
            if global_data and boolify(global_data[internet_protocol.value].lower()):
                exportable[internet_protocol] = True
                self.metric_sag_info.labels(
                    internet_protocol.value.lower(), _decode(global_data["gwmac"])
                ).set(1)

        if not keys or not vxlan_tunnel_map:
            return
        vxlan_tunnel_map = list(vxlan_tunnel_map)
        for key in keys:
            ## ["interface", "vrf", "gateway_ip", "ip_family", "vni"]
            data = key.replace(SAG, "")
            interface, ip_family = data.split("|")
            ip_family = InternetProtocol(ip_family)
            if exportable[ip_family]:
                try:
                    vrf = _decode(
                        self.sonic_db.get(
                            self.sonic_db.CONFIG_DB,
                            f"{VLAN_INTERFACE}{interface}",
                            "vrf_name",
                        )
                    )
                    gateway_ip = _decode(
                        self.sonic_db.get(self.sonic_db.CONFIG_DB, key, "gwip@")
                    )
                    vni_key = next(
                        vxlan_tunnel_key
                        for vxlan_tunnel_key in vxlan_tunnel_map
                        if _decode(vxlan_tunnel_key).endswith(interface)
                    )
                    vni = _decode(
                        self.sonic_db.get(self.sonic_db.CONFIG_DB, vni_key, "vni")
                    )
                    self.metric_sag_admin_status.labels(
                        interface, vrf, gateway_ip, ip_family.value.lower(), vni
                    ).set(self.sys_class_net.admin_enabled(interface))
                    self.metric_sag_operational_status.labels(
                        interface, vrf, gateway_ip, ip_family.value.lower(), vni
                    ).set(self.sys_class_net.operational(interface))
                except (KeyError, StopIteration):
                    logging.debug(
                        f"export_static_anycast_gateway_info : No Static Anycast Gateway for interface={interface}"
                    )
                    pass

    def export_bgp_info(self):
        # vtysh -c "show bgp vrf all ipv4 unicast summary json"
        # vtysh -c "show bgp vrf all ipv6 unicast summary json"
        # vtysh -c "show bgp vrf all l2vpn evpn summary json"
        # vtysh -c "show bgp vrf all summary json"
        #
        ## BGP Peerings
        ##
        ## Labels
        # peer_type = ipv4/ipv6
        # vrf = vrf_namen
        # neighbor = dns namen / ip | hostname for servers
        # remote_as = as_nummer
        # bgp_protocol_type = evpn/ipv4/ipv6
        ## Metrik
        # Uptime
        # Received Prefixes
        # Sent Prefixes
        # status
        bgp_vrf_all = self.vtysh.show_bgp_vrf_all_summary()
        for vrf in bgp_vrf_all:
            for family in AddressFamily:
                family_data = None
                try:
                    family_data = bgp_vrf_all[vrf][family.value]
                    for peername, peerdata in family_data["peers"].items():
                        # ["vrf", "peername", "neighbor", "peer_protocol", "protocol_family_advertised", "remote_as"]
                        self.metric_bgp_uptime_seconds.labels(
                            vrf,
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ).set(floatify(peerdata.get("peerUptimeMsec", 1000) / 1000))
                        self.metric_bgp_status.labels(
                            vrf,
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ).set(boolify(peerdata.get("state", "")))
                        self.metric_bgp_prefixes_received.labels(
                            vrf,
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ).set(floatify(peerdata.get("pfxRcd", 0)))
                        self.metric_bgp_prefixes_transmitted.labels(
                            vrf,
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ).set(floatify(peerdata.get("pfxSnt", 0)))
                        self.metric_bgp_messages_received.labels(
                            vrf,
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ).set(floatify(peerdata.get("msgRcvd", 0)))
                        self.metric_bgp_messages_transmitted.labels(
                            vrf,
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ).set(floatify(peerdata.get("pfxSnt", 0)))
                except KeyError:
                    pass

    def export_evpn_vni_info(self):

        evpn_vni_detail = self.vtysh.show_evpn_vni_detail()
        for evpn_vni in evpn_vni_detail:
            vni = _decode(str(evpn_vni["vni"]))
            interface = ""
            svi = ""
            layer = _decode(OSILayer(evpn_vni["type"].lower()))
            vrf = _decode(evpn_vni["vrf"])
            state = False
            match layer:
                case OSILayer.L3:
                    svi = _decode(evpn_vni["sviIntf"])
                    interface = _decode(evpn_vni["vxlanIntf"])
                    state = _decode(evpn_vni["state"].lower())
                    self.metric_evpn_l2_vnis.labels(
                        vni, interface, svi, layer.value, vrf
                    ).set(floatify(len(evpn_vni["l2Vnis"])))
                case OSILayer.L2:
                    interface = _decode(evpn_vni["vxlanInterface"])
                    state = self.sys_class_net.operational(interface)
                    self.metric_evpn_remote_vteps.labels(
                        vni, interface, svi, layer.value, vrf
                    ).set(floatify(len(evpn_vni.get("numRemoteVteps", []))))
                    self.metric_evpn_arps.labels(
                        vni, interface, svi, layer.value, vrf
                    ).set(evpn_vni["numArpNd"])
                    self.metric_evpn_mac_addresses.labels(
                        vni, interface, svi, layer.value, vrf
                    ).set(floatify(evpn_vni["numMacs"]))
            self.metric_evpn_status.labels(vni, interface, svi, layer.value, vrf).set(
                boolify(state)
            )

    def start_export(self):
        try:
            self.export_interface_counters()
            self.export_interface_queue_counters()
            self.export_interface_cable_data()
            self.export_interface_optic_data()
            self.export_system_info()
            self.export_psu_info()
            self.export_fan_info()
            self.export_temp_info()
            self.export_vxlan_tunnel_info()
            self.export_bgp_info()
            self.export_evpn_vni_info()
            self.export_static_anycast_gateway_info()
        except KeyboardInterrupt as e:
            raise e


def main():
    data_extract_interval = floatify(
        os.environ.get("REDIS_COLLECTION_INTERVAL", 30)
    )  # considering 30 seconds as default collection interval
    port = int(
        os.environ.get("SONIC_EXPORTER_PORT", 9101)
    )  # setting port static as 9101. if required map it to someother port of host by editing compose file.
    address = str(os.environ.get("SONIC_EXPORTER_ADDRESS", "localhost"))
    exp = Export(os.environ.get("DEVELOPER_MODE", "False").lower() in TRUE_VALUES)
    logging.info("Starting Python exporter server at port 9101")
    prom.start_http_server(port, addr=address)

    while True:
        exp.start_export()
        logging.info("Export Done!")
        time.sleep(data_extract_interval)


def cli():
    try:
        file_path = os.path.dirname(__file__)
        if file_path != "":
            os.chdir(file_path)
        main()
    except KeyboardInterrupt:
        sys.exit(0)
