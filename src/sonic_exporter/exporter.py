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
import os
import logging
import logging.config
import json
import re
import socket
import subprocess
import yaml
import sys
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
from datetime import datetime

import prometheus_client as prom
from prometheus_client.core import REGISTRY, CounterMetricFamily, GaugeMetricFamily

from sonic_exporter.constants import (
    CHASSIS_INFO,
    CHASSIS_INFO_PATTERN,
    MCLAG_DOMAIN,
    MCLAG_DOMAIN_PATTERN,
    MCLAG_TABLE,
    MCLAG_TABLE_PATTERN,
    COUNTER_IGNORE,
    COUNTER_PORT_MAP,
    COUNTER_QUEUE_MAP,
    COUNTER_QUEUE_TYPE_MAP,
    COUNTER_TABLE_PREFIX,
    EEPROM_INFO,
    EEPROM_INFO_PATTERN,
    FAN_INFO_PATTERN,
    NTP_SERVER,
    NTP_SERVER_PATTERN,
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
from sonic_exporter.enums import (
    AddressFamily,
    AirFlow,
    AlarmType,
    InternetProtocol,
    OSILayer,
    SwitchModel,
)
from sonic_exporter.utilities import ConfigDBVersion, timed_cache

BASE_PATH = Path(__file__).parent


class SONiCCollector(object):
    rx_power_regex = re.compile(r"^rx(\d*)power$")
    tx_power_regex = re.compile(r"^tx(\d*)power$")
    tx_bias_regex = re.compile(r"^tx(\d*)bias$")
    fan_slot_regex = re.compile(r"^((?:PSU|Fantray).*?\d+).*?(?!FAN|_).*?(\d+)$")
    chassis_slot_regex = re.compile(r"^.*?(\d+)$")
    db_default_retries = 1
    # timeout applicable only when retries >1
    db_default_timeout = 3

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

    # Non default values of retries and timeout are usefull for DB calls, when DB may not be ready to serve requests
    # e.g. right after SONiC boots up while getting sonic system status from DB.

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

    def __init__(self, developer_mode: bool):
        if developer_mode:
            import sonic_exporter.test.mock_db as mock_db
            from sonic_exporter.test.mock_sys_class_hwmon import MockSystemClassHWMon
            from sonic_exporter.test.mock_sys_class_net import (
                MockSystemClassNetworkInfo,
            )
            from sonic_exporter.test.mock_vtysh import MockVtySH
            from sonic_exporter.test.mock_ntpq import MockNTPQ

            self.vtysh = MockVtySH()
            self.sys_class_net = MockSystemClassNetworkInfo()
            self.sys_class_hwmon = MockSystemClassHWMon()
            self.ntpq = MockNTPQ()
            self.sonic_db = mock_db.SonicV2Connector(password="")
        else:
            import swsssdk

            from sonic_exporter.sys_class_hwmon import SystemClassHWMon
            from sonic_exporter.sys_class_net import SystemClassNetworkInfo
            from sonic_exporter.vtysh import VtySH
            from sonic_exporter.ntpq import NTPQ

            self.vtysh = VtySH()
            self.sys_class_net = SystemClassNetworkInfo()
            self.sys_class_hwmon = SystemClassHWMon()
            try:
                with open("/run/redis/auth/passwd", "r") as secret:
                    self.sonic_db = swsssdk.SonicV2Connector(password=secret.read().strip())
            except FileNotFoundError:
                self.sonic_db = swsssdk.SonicV2Connector()
            self.ntpq = NTPQ()

        self.sonic_db.connect(self.sonic_db.COUNTERS_DB)
        self.sonic_db.connect(self.sonic_db.STATE_DB)
        self.sonic_db.connect(self.sonic_db.APPL_DB)
        self.sonic_db.connect(self.sonic_db.CONFIG_DB)
        self.thread_pool = ThreadPoolExecutor(10)
        self.db_version = ConfigDBVersion(
            _decode(
                self.getFromDB(
                    self.sonic_db.CONFIG_DB, "VERSIONS|DATABASE", "VERSION", retries=15
                )
            )
        )

        if not self.is_sonic_sys_ready(retries=15):
            self.logger.error(
                "SONiC System isn't ready even after several retries, exiting sonic-exporter."
            )
            sys.exit(0)

        self.logger.info("SONiC System is ready.")

        self.chassis = {
            _decode(key).replace(CHASSIS_INFO, ""): self.getAllFromDB(
                self.sonic_db.STATE_DB, key
            )
            for key in self.getKeysFromDB(self.sonic_db.STATE_DB, CHASSIS_INFO_PATTERN)
        }

        self.syseeprom = {
            _decode(key)
            .replace(EEPROM_INFO, "")
            .replace(" ", "_")
            .lower(): self.getAllFromDB(self.sonic_db.STATE_DB, key)
            for key in self.getKeysFromDB(self.sonic_db.STATE_DB, EEPROM_INFO_PATTERN)
        }

        self.platform_name: str = list(
            set(
                _decode(chassis.get("platform_name", ""))
                for chassis in self.chassis.values()
            )
        )[0].strip()
        if not self.platform_name:
            self.platform_name = self._find_in_syseeprom("platform_name")
        self.product_name = list(
            set(
                _decode(chassis.get("product_name", ""))
                for chassis in self.chassis.values()
            )
        )[0].strip()
        if not self.product_name:
            self.product_name = self._find_in_syseeprom("product_name")

    def _find_in_syseeprom(self, key: str):
        return list(
            set(
                syseeprom.get("Value", "")
                for syseeprom in self.syseeprom.values()
                if str(syseeprom.get("Name", "")).replace(" ", "_").lower() == key
            )
        )[0].strip()

    def is_sonic_sys_ready(
        self, retries=db_default_retries, timeout=db_default_timeout
    ):
        sts = self.getFromDB(
            self.sonic_db.STATE_DB,
            "SYSTEM_READY|SYSTEM_STATE",
            "Status",
            retries=retries,
            timeout=timeout,
        )
        sts_core = sts
        if self.db_version > ConfigDBVersion("version_4_0_0"):
            ## this feature is only supported in newer ConfigDBs
            ## Especially version_3_4_1 does not have this flag
            ## so we use the sts flag for backwards compatible code.
            sts_core = self.getFromDB(
                self.sonic_db.STATE_DB,
                "SYSTEM_READY_CORE|SYSTEM_STATE",
                "Status",
                retries=retries,
                timeout=timeout,
            )
        sts = True if sts and "UP" in sts else False
        sts_core = True if sts and "UP" in sts_core else False
        return sts, sts_core

    def _init_metrics(self):
        # at start of server get counters data and negate it with current data while exporting
        # Interface counters
        interface_labels = ["interface"]
        port_label = ["port"]
        bgp_labels = [
            "vrf",
            "as",
            "peer_name",
            "peer_host",
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

        self.metric_ntp_peers = GaugeMetricFamily(
            "sonic_ntp_peers",
            "NTP peers",
            labels=["remote", "refid", "st", "t", "poll", "reach", "state"],
        )

        self.metric_mclag_domain = GaugeMetricFamily(
            "sonic_mclag_domain",
            "MCLAG Domain",
            labels=[
                "domain_id",
                "source_ip",
                "keepalive_interval",
                "session_timeout",
                "peer_ip",
                "peer_link",
                "mclag_system_mac",
            ],
        )

        self.metric_mclag_oper_state = GaugeMetricFamily(
            "sonic_mclag_oper_state",
            "MCLAG Operational State",
            labels=[
                "domain_id",
                "mclag_system_mac",
                "role",
                "system_mac",
                "peer_mac",
                "reason",
            ],
        )

        self.metric_sys_status = GaugeMetricFamily(
            "sonic_system_status",
            "SONiC System Status",
            labels=["status", "status_core"],
        )

        self.metric_ntp_sync_status = GaugeMetricFamily(
            "sonic_ntp_sync_status",
            "SONiC NTP Sync Status (0/1 0==Not in Sync 1==Sync)",
        )
        self.metric_ntp_when = GaugeMetricFamily(
            "sonic_ntp_when",
            "Time (in seconds) since an NTP packet update was received",
            labels=["remote", "refid"],
        )

        self.metric_ntp_rtd = GaugeMetricFamily(
            "sonic_ntp_rtd",
            "Round-trip delay (in milliseconds) to the NTP server.",
            labels=["remote", "refid"],
        )

        self.metric_ntp_offset = GaugeMetricFamily(
            "sonic_ntp_offset",
            "Time difference (in milliseconds) between the switch and the NTP server or another NTP peer.",
            labels=["remote", "refid"],
        )

        self.metric_ntp_jitter = GaugeMetricFamily(
            "sonic_ntp_jitter",
            "Mean deviation in times between the switch and the NTP server",
            labels=["remote", "refid"],
        )

        self.metric_ntp_global = GaugeMetricFamily(
            "sonic_ntp_global",
            "NTP Global",
            labels=["vrf", "auth_enabled", "src_intf", "trusted_key"],
        )

        self.metric_ntp_server = GaugeMetricFamily(
            "sonic_ntp_server",
            "NTP Servers",
            labels=["ntp_server", "key_id", "minpoll", "maxpoll"],
        )

        self.metric_interface_info = GaugeMetricFamily(
            "sonic_interface_info",
            "Interface Information (Description, MTU, Speed)",
            labels=interface_labels + ["description", "mtu", "speed", "device"],
        )
        self.metric_interface_speed = GaugeMetricFamily(
            "sonic_interface_speed_bytes",
            "The maximum interface speed in bytes per second",
            labels=interface_labels,
        )
        self.metric_interface_transmitted_bytes = CounterMetricFamily(
            "sonic_interface_transmitted_bytes_total",
            "Total transmitted Bytes by Interface",
            labels=interface_labels,
        )
        self.metric_interface_received_bytes = CounterMetricFamily(
            "sonic_interface_received_bytes_total",
            "Total received Bytes by Interface",
            labels=interface_labels,
        )
        self.metric_interface_transmitted_packets = CounterMetricFamily(
            "sonic_interface_transmitted_packets_total",
            "Total transmitted Packets by Interface",
            labels=interface_labels + ["delivery_mode"],
        )
        self.metric_interface_received_packets = CounterMetricFamily(
            "sonic_interface_received_packets_total",
            "Total received Packets by Interface",
            labels=interface_labels + ["delivery_mode"],
        )
        self.metric_interface_receive_error_input_packets = CounterMetricFamily(
            "sonic_interface_receive_error_input_packets_total",
            "Errors in received packets",
            labels=interface_labels + ["cause"],
        )
        self.metric_interface_transmit_error_output_packets = CounterMetricFamily(
            "sonic_interface_transmit_error_output_packets_total",
            "Errors in transmitted packets",
            labels=interface_labels + ["cause"],
        )
        self.metric_interface_received_ethernet_packets = CounterMetricFamily(
            "sonic_interface_received_ethernet_packets_total",
            "Size of the Ethernet Frames received",
            labels=interface_labels + ["packet_size"],
        )
        self.metric_interface_transmitted_ethernet_packets = CounterMetricFamily(
            "sonic_interface_transmitted_ethernet_packets_total",
            "Size of the Ethernet Frames transmitted",
            labels=interface_labels + ["packet_size"],
        )
        # Interface Status Gauges
        self.metric_interface_operational_status = GaugeMetricFamily(
            "sonic_interface_operational_status",
            "The Operational Status reported from the Device (0(DOWN)/1(UP))",
            labels=interface_labels,
        )
        self.metric_interface_admin_status = GaugeMetricFamily(
            "sonic_interface_admin_status",
            "The Configuration Status reported from the Device (0(DOWN)/1(UP))",
            labels=interface_labels,
        )
        self.metric_interface_last_flapped_seconds = CounterMetricFamily(
            "sonic_interface_last_flapped_seconds_total",
            "The Timestamp as Unix Timestamp since the last flap of the interface.",
            labels=interface_labels,
        )
        # Queue Counters
        self.metric_interface_queue_processed_packets = CounterMetricFamily(
            "sonic_interface_queue_processed_packets_total",
            "Interface queue counters",
            labels=interface_labels + ["queue"] + ["delivery_mode"],
        )
        self.metric_interface_queue_processed_bytes = CounterMetricFamily(
            "sonic_interface_queue_processed_bytes_total",
            "Interface queue counters",
            labels=interface_labels + ["queue"] + ["delivery_mode"],
        )
        # Optic Health Information
        self.metric_interface_receive_optic_power_dbm = GaugeMetricFamily(
            "sonic_interface_receive_optic_power_dbm",
            "Power value for all the interfaces",
            labels=port_label + interface_labels + ["optic_unit"],
        )
        self.metric_interface_transmit_optic_power_dbm = GaugeMetricFamily(
            "sonic_interface_transmit_optic_power_dbm",
            "Power value for all the interfaces",
            labels=port_label + interface_labels + ["optic_unit"],
        )
        self.metric_interface_transmit_optic_bias_amperes = GaugeMetricFamily(
            "sonic_interface_transmit_optic_bias_amperes",
            "Transmit Bias Current for all optics in the interface",
            labels=port_label + interface_labels + ["optic_unit"],
        )
        self.metric_interface_optic_celsius = GaugeMetricFamily(
            "sonic_interface_optic_celsius",
            "Temperature for all interfaces",
            labels=port_label + interface_labels,
        )
        self.metric_interface_optic_volts = GaugeMetricFamily(
            "sonic_interface_optic_volts",
            "Voltage of all transceiver optics per interface",
            labels=port_label + interface_labels,
        )
        self.metric_transceiver_threshold_info = GaugeMetricFamily(
            "sonic_transceiver_threshold_info",
            "Thresholds info for the transceivers inserted",
            labels=port_label
            + interface_labels
            + [
                "vcchighalarm",
                "vcchighwarning",
                "vcclowalarm",
                "vcclowwarning",
                "temphighalarm",
                "temphighwarning",
                "templowalarm",
                "templowwarning",
                "txbiashighalarm",
                "txbiashighwarning",
                "txbiaslowalarm",
                "txbiaslowwarning",
                "txpowerhighalarm",
                "txpowerhighwarning",
                "txpowerlowalarm",
                "txpowerlowwarning",
                "rxpowerhighalarm",
                "rxpowerhighwarning",
                "rxpowerlowalarm",
                "rxpowerlowwarning",
            ],
        )
        # Transceiver Info
        self.metric_interface_transceiver_info = GaugeMetricFamily(
            "sonic_interface_transceiver_info",
            "General Information about the transceivers per Interface",
            labels=interface_labels
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
        self.metric_interface_cable_length_meters = GaugeMetricFamily(
            "sonic_interface_cable_length_meters",
            "The length of the plugged in Cable",
            labels=interface_labels + ["cable_type", "connector_type"],
        )
        # PSU Info
        self.metric_device_psu_input_volts = GaugeMetricFamily(
            "sonic_device_psu_input_volts",
            "The Amount of Voltage provided to the power supply",
            labels=["slot"],
        )
        self.metric_device_psu_input_amperes = GaugeMetricFamily(
            "sonic_device_psu_input_amperes",
            "The Amount of Amperes provided to the power supply",
            labels=["slot"],
        )
        self.metric_device_psu_output_volts = GaugeMetricFamily(
            "sonic_device_psu_output_volts",
            "The Amount of Voltage provided to the internal system",
            labels=["slot"],
        )
        self.metric_device_psu_output_amperes = GaugeMetricFamily(
            "sonic_device_psu_output_amperes",
            "The Amount of Amperes used by the system",
            labels=["slot"],
        )
        self.metric_device_psu_operational_status = GaugeMetricFamily(
            "sonic_device_psu_operational_status",
            "Shows if a power supply is Operational (0(DOWN)/1(UP))",
            labels=["slot"],
        )
        self.metric_device_psu_available_status = GaugeMetricFamily(
            "sonic_device_psu_available_status",
            "Shows if a power supply is plugged in (0(DOWN)/1(UP))",
            labels=["slot"],
        )
        self.metric_device_psu_celsius = GaugeMetricFamily(
            "sonic_device_psu_celsius",
            "The Temperature in Celsius of the PSU",
            labels=["slot"],
        )
        self.metric_device_psu_info = GaugeMetricFamily(
            "sonic_device_psu_info",
            "More information of the psu",
            labels=["slot", "serial", "model_name", "model"],
        )
        # FAN Info
        self.metric_device_fan_rpm = GaugeMetricFamily(
            "sonic_device_fan_rpm",
            "The Rounds per minute of the fan",
            labels=["name", "slot"],
        )
        self.metric_device_fan_operational_status = GaugeMetricFamily(
            "sonic_device_fan_operational_status",
            "Shows if a fan is Operational (0(DOWN)/1(UP))",
            labels=["name", "slot"],
        )
        self.metric_device_fan_available_status = GaugeMetricFamily(
            "sonic_device_fan_available_status",
            "Shows if a fan is plugged in (0(DOWN)/1(UP))",
            labels=["name", "slot"],
        )
        # Temp Info
        self.metric_device_sensor_celsius = GaugeMetricFamily(
            "sonic_device_sensor_celsius",
            "Show the temperature of the Sensors in the switch",
            labels=["name"],
        )
        self.metric_device_threshold_sensor_celsius = GaugeMetricFamily(
            "sonic_device_sensor_threshold_celsius",
            f"Thresholds for the temperature sensors {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            labels=["name", "alarm_type"],
        )
        # VXLAN Tunnel Info
        self.metric_vxlan_operational_status = GaugeMetricFamily(
            "sonic_vxlan_operational_status",
            "Reports the status of the VXLAN Tunnel to Endpoints (0(DOWN)/1(UP))",
            labels=["neighbor"],
        )
        # System Info
        self.metric_device_uptime = CounterMetricFamily(
            "sonic_device_uptime_seconds_total", "The uptime of the device in seconds"
        )
        self.metric_device_info = GaugeMetricFamily(
            "sonic_device_info",
            "part name, serial number, MAC address and software vesion of the System",
            labels=[
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
        self.system_memory_ratio = GaugeMetricFamily(
            "sonic_device_memory_ratio",
            "Memory Usage of the device in percentage [0-1]",
        )
        self.system_cpu_ratio = GaugeMetricFamily(
            "sonic_device_cpu_ratio", "CPU Usage of the device in percentage [0-1]"
        )
        # BGP Info
        self.metric_bgp_uptime_seconds = CounterMetricFamily(
            "sonic_bgp_uptime_seconds_total",
            "Uptime of the session with the other BGP Peer",
            labels=bgp_labels,
        )
        self.metric_bgp_status = GaugeMetricFamily(
            "sonic_bgp_status",
            "The Session Status to the other BGP Peer",
            labels=bgp_labels,
        )
        self.metric_bgp_prefixes_received = CounterMetricFamily(
            "sonic_bgp_prefixes_received_total",
            "The Prefixes Received from the other peer.",
            labels=bgp_labels,
        )
        self.metric_bgp_prefixes_transmitted = CounterMetricFamily(
            "sonic_bgp_prefixes_transmitted_total",
            "The Prefixes Transmitted to the other peer.",
            labels=bgp_labels,
        )
        self.metric_bgp_messages_received = CounterMetricFamily(
            "sonic_bgp_messages_received_total",
            "The messages Received from the other peer.",
            labels=bgp_labels,
        )
        self.metric_bgp_messages_transmitted = CounterMetricFamily(
            "sonic_bgp_messages_transmitted_total",
            "The messages Transmitted to the other peer.",
            labels=bgp_labels,
        )
        # Static Anycast Gateway
        self.metric_sag_operational_status = GaugeMetricFamily(
            "sonic_sag_operational_status",
            "Reports the operational status of the Static Anycast Gateway (0(DOWN)/1(UP))",
            labels=sag_labels,
        )
        self.metric_sag_admin_status = GaugeMetricFamily(
            "sonic_sag_admin_status",
            "Reports the admin status of the Static Anycast Gateway (0(DOWN)/1(UP))",
            labels=sag_labels,
        )
        self.metric_sag_info = GaugeMetricFamily(
            "sonic_sag_info",
            "Static Anycast Gateway General Information",
            labels=["ip_family", "mac_address"],
        )
        # EVPN Information
        self.metric_evpn_status = GaugeMetricFamily(
            "sonic_evpn_status",
            "The Status of the EVPN Endpoints",
            labels=evpn_vni_labels,
        )
        self.metric_evpn_remote_vteps = GaugeMetricFamily(
            "sonic_evpn_remote_vteps",
            "The number of remote VTEPs associated with that VNI",
            labels=evpn_vni_labels,
        )

        self.metric_evpn_l2_vnis = GaugeMetricFamily(
            "sonic_evpn_l2_vnis",
            "The number of l2 vnis associated with an l3 VNI",
            labels=evpn_vni_labels,
        )
        self.metric_evpn_mac_addresses = GaugeMetricFamily(
            "sonic_evpn_mac_addresses",
            "The number of Mac Addresses learned VNI",
            labels=evpn_vni_labels,
        )
        self.metric_evpn_arps = GaugeMetricFamily(
            "sonic_evpn_arps",
            "The number of ARPs cached for the VNI",
            labels=evpn_vni_labels,
        )

        self.crm_acl_stats_egress_lag_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_lag_crm_stats_acl_group_used",
            "crm_acl_stats_egress_lag_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_egress_lag_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_lag_crm_stats_acl_table_used",
            "crm_acl_stats_egress_lag_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_egress_lag_crm_stats_acl_group_available = GaugeMetricFamily(
            "crm_acl_stats_egress_lag_crm_stats_acl_group_available",
            "crm_acl_stats_egress_lag_crm_stats_acl_group_available",
        )
        self.crm_acl_stats_egress_lag_crm_stats_acl_table_available = GaugeMetricFamily(
            "crm_acl_stats_egress_lag_crm_stats_acl_table_available",
            "crm_acl_stats_egress_lag_crm_stats_acl_table_available",
        )

        self.crm_acl_stats_egress_port_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_port_crm_stats_acl_group_used",
            "crm_acl_stats_egress_port_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_egress_port_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_port_crm_stats_acl_table_used",
            "crm_acl_stats_egress_port_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_egress_port_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_egress_port_crm_stats_acl_group_available",
                "crm_acl_stats_egress_port_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_egress_port_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_egress_port_crm_stats_acl_table_available",
                "crm_acl_stats_egress_port_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_egress_rif_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_rif_crm_stats_acl_group_used",
            "crm_acl_stats_egress_rif_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_egress_rif_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_rif_crm_stats_acl_table_used",
            "crm_acl_stats_egress_rif_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_egress_rif_crm_stats_acl_group_available = GaugeMetricFamily(
            "crm_acl_stats_egress_rif_crm_stats_acl_group_available",
            "crm_acl_stats_egress_rif_crm_stats_acl_group_available",
        )
        self.crm_acl_stats_egress_rif_crm_stats_acl_table_available = GaugeMetricFamily(
            "crm_acl_stats_egress_rif_crm_stats_acl_table_available",
            "crm_acl_stats_egress_rif_crm_stats_acl_table_available",
        )

        self.crm_acl_stats_egress_switch_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_switch_crm_stats_acl_group_used",
            "crm_acl_stats_egress_switch_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_egress_switch_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_switch_crm_stats_acl_table_used",
            "crm_acl_stats_egress_switch_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_egress_switch_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_egress_switch_crm_stats_acl_group_available",
                "crm_acl_stats_egress_switch_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_egress_switch_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_egress_switch_crm_stats_acl_table_available",
                "crm_acl_stats_egress_switch_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_egress_vlan_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_vlan_crm_stats_acl_group_used",
            "crm_acl_stats_egress_vlan_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_egress_vlan_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_vlan_crm_stats_acl_table_used",
            "crm_acl_stats_egress_vlan_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_egress_vlan_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_egress_vlan_crm_stats_acl_group_available",
                "crm_acl_stats_egress_vlan_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_egress_vlan_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_egress_vlan_crm_stats_acl_table_available",
                "crm_acl_stats_egress_vlan_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_ingress_lag_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_lag_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_lag_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_ingress_lag_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_lag_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_lag_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_ingress_lag_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_lag_crm_stats_acl_group_available",
                "crm_acl_stats_ingress_lag_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_ingress_lag_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_lag_crm_stats_acl_table_available",
                "crm_acl_stats_ingress_lag_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_ingress_port_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_port_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_port_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_ingress_port_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_port_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_port_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_ingress_port_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_port_crm_stats_acl_group_available",
                "crm_acl_stats_ingress_port_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_ingress_port_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_port_crm_stats_acl_table_available",
                "crm_acl_stats_ingress_port_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_ingress_rif_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_rif_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_rif_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_ingress_rif_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_rif_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_rif_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_ingress_rif_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_rif_crm_stats_acl_group_available",
                "crm_acl_stats_ingress_rif_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_ingress_rif_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_rif_crm_stats_acl_table_available",
                "crm_acl_stats_ingress_rif_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_ingress_switch_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_switch_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_switch_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_ingress_switch_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_switch_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_switch_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_ingress_switch_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_switch_crm_stats_acl_group_available",
                "crm_acl_stats_ingress_switch_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_ingress_switch_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_switch_crm_stats_acl_table_available",
                "crm_acl_stats_ingress_switch_crm_stats_acl_table_available",
            )
        )

        self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_vlan_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_vlan_crm_stats_acl_group_used",
        )
        self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_vlan_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_vlan_crm_stats_acl_table_used",
        )
        self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_vlan_crm_stats_acl_group_available",
                "crm_acl_stats_ingress_vlan_crm_stats_acl_group_available",
            )
        )
        self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_available = (
            GaugeMetricFamily(
                "crm_acl_stats_ingress_vlan_crm_stats_acl_table_available",
                "crm_acl_stats_ingress_vlan_crm_stats_acl_table_available",
            )
        )

        self.crm_stats_dnat_entry_used = GaugeMetricFamily(
            "crm_stats_dnat_entry_used", "crm_stats_dnat_entry_used"
        )
        self.crm_stats_fdb_entry_used = GaugeMetricFamily(
            "crm_stats_fdb_entry_used", "crm_stats_fdb_entry_used"
        )
        self.crm_stats_ipmc_entry_used = GaugeMetricFamily(
            "crm_stats_ipmc_entry_used", "crm_stats_ipmc_entry_used"
        )
        self.crm_stats_ipv4_neighbor_used = GaugeMetricFamily(
            "crm_stats_ipv4_neighbor_used", "crm_stats_ipv4_neighbor_used"
        )
        self.crm_stats_ipv4_nexthop_used = GaugeMetricFamily(
            "crm_stats_ipv4_nexthop_used", "crm_stats_ipv4_nexthop_used"
        )
        self.crm_stats_ipv4_route_used = GaugeMetricFamily(
            "crm_stats_ipv4_route_used", "crm_stats_ipv4_route_used"
        )
        self.crm_stats_ipv6_neighbor_used = GaugeMetricFamily(
            "crm_stats_ipv6_neighbor_used", "crm_stats_ipv6_neighbor_used"
        )
        self.crm_stats_ipv6_nexthop_used = GaugeMetricFamily(
            "crm_stats_ipv6_nexthop_used", "crm_stats_ipv6_nexthop_used"
        )
        self.crm_stats_ipv6_route_used = GaugeMetricFamily(
            "crm_stats_ipv6_route_used", "crm_stats_ipv6_route_used"
        )
        self.crm_stats_nexthop_group_member_used = GaugeMetricFamily(
            "crm_stats_nexthop_group_member_used", "crm_stats_nexthop_group_member_used"
        )
        self.crm_stats_nexthop_group_used = GaugeMetricFamily(
            "crm_stats_nexthop_group_used", "crm_stats_nexthop_group_used"
        )
        self.crm_stats_snat_entry_used = GaugeMetricFamily(
            "crm_stats_snat_entry_used", "crm_stats_snat_entry_used"
        )
        self.crm_stats_dnat_entry_available = GaugeMetricFamily(
            "crm_stats_dnat_entry_available", "crm_stats_dnat_entry_available"
        )
        self.crm_stats_fdb_entry_available = GaugeMetricFamily(
            "crm_stats_fdb_entry_available", "crm_stats_fdb_entry_available"
        )
        self.crm_stats_ipmc_entry_available = GaugeMetricFamily(
            "crm_stats_ipmc_entry_available", "crm_stats_ipmc_entry_available"
        )
        self.crm_stats_ipv4_neighbor_available = GaugeMetricFamily(
            "crm_stats_ipv4_neighbor_available", "crm_stats_ipv4_neighbor_available"
        )
        self.crm_stats_ipv4_nexthop_available = GaugeMetricFamily(
            "crm_stats_ipv4_nexthop_available", "crm_stats_ipv4_nexthop_available"
        )
        self.crm_stats_ipv4_route_available = GaugeMetricFamily(
            "crm_stats_ipv4_route_available", "crm_stats_ipv4_route_available"
        )
        self.crm_stats_ipv6_neighbor_available = GaugeMetricFamily(
            "crm_stats_ipv6_neighbor_available", "crm_stats_ipv6_neighbor_available"
        )
        self.crm_stats_ipv6_nexthop_available = GaugeMetricFamily(
            "crm_stats_ipv6_nexthop_available", "crm_stats_ipv6_nexthop_available"
        )
        self.crm_stats_ipv6_route_available = GaugeMetricFamily(
            "crm_stats_ipv6_route_available", "crm_stats_ipv6_route_available"
        )
        self.crm_stats_nexthop_group_available = GaugeMetricFamily(
            "crm_stats_nexthop_group_available", "crm_stats_nexthop_group_available"
        )
        self.crm_stats_nexthop_group_member_available = GaugeMetricFamily(
            "crm_stats_nexthop_group_member_available",
            "crm_stats_nexthop_group_member_available",
        )
        self.crm_stats_snat_entry_available = GaugeMetricFamily(
            "crm_stats_snat_entry_available", "crm_stats_snat_entry_available"
        )

    def get_portinfo(self, ifname, sub_key):
        if ifname.startswith("Ethernet"):
            key = f"PORT|{ifname}"
        else:
            key = f"PORTCHANNEL|{ifname}"
        try:
            return _decode(self.getFromDB(self.sonic_db.CONFIG_DB, key, sub_key))
        except (ValueError, KeyError):
            return ""

    def get_additional_info(self, ifname):
        return self.get_portinfo(ifname, "alias") or ifname

    def export_vxlan_tunnel_info(self):
        keys = self.getKeysFromDB(self.sonic_db.STATE_DB, VXLAN_TUNNEL_TABLE_PATTERN)
        if not keys:
            return
        for key in keys:
            try:
                neighbor = ""
                _, neighbor = tuple(key.replace(VXLAN_TUNNEL_TABLE, "").split("_"))
                is_operational = boolify(
                    _decode(self.getFromDB(self.sonic_db.STATE_DB, key, "operstatus"))
                )
                self.metric_vxlan_operational_status.add_metric(
                    [self.dns_lookup(neighbor)], is_operational
                )
                self.logger.debug(
                    f"export_vxlan_tunnel :: neighbor={neighbor}, is_operational={is_operational}"
                )
            except ValueError as e:
                pass

    def export_interface_counters(self):
        maps = self.getAllFromDB(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        for ifname in maps:
            counter_key = SONiCCollector.get_counter_key(_decode(maps[ifname]))
            ifname_decoded = _decode(ifname)
            # this should be GBit/s
            if ifname_decoded.lower() in COUNTER_IGNORE:
                continue
            interface_speed = (
                int(round(int(self.get_portinfo(ifname, "speed"))) / 1000)
                if self.get_portinfo(ifname, "speed")
                else 0
            )
            self.metric_interface_info.add_metric(
                [
                    self.get_additional_info(ifname),
                    self.get_portinfo(ifname, "description"),
                    self.get_portinfo(ifname, "mtu"),
                    f"{interface_speed}Gbps",
                    ifname,
                ],
                1,
            )
            self.metric_interface_speed.add_metric(
                [self.get_additional_info(ifname)],
                floatify(interface_speed * 1000 * 1000 * 1000 / 8),
            )

            # Ethernet RX
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
                self.metric_interface_received_ethernet_packets.add_metric(
                    [self.get_additional_info(ifname), str(size)],
                    floatify(
                        _decode(
                            self.getFromDB(self.sonic_db.COUNTERS_DB, counter_key, key)
                        )
                    ),
                )
            # Ethernet TX
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
                self.metric_interface_transmitted_ethernet_packets.add_metric(
                    [self.get_additional_info(ifname), str(size)],
                    floatify(
                        _decode(
                            self.getFromDB(self.sonic_db.COUNTERS_DB, counter_key, key)
                        )
                    ),
                )
            # RX
            self.metric_interface_received_bytes.add_metric(
                [self.get_additional_info(ifname)],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_OCTETS",
                    )
                ),
            )
            self.metric_interface_received_packets.add_metric(
                [self.get_additional_info(ifname), "unicast"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                    )
                ),
            )
            self.metric_interface_received_packets.add_metric(
                [self.get_additional_info(ifname), "multicast"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS",
                    )
                ),
            )
            self.metric_interface_received_packets.add_metric(
                [self.get_additional_info(ifname), "broadcast"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS",
                    )
                ),
            )

            # RX Errors
            self.metric_interface_receive_error_input_packets.add_metric(
                [self.get_additional_info(ifname), "error"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_ERRORS",
                    )
                ),
            )
            self.metric_interface_receive_error_input_packets.add_metric(
                [self.get_additional_info(ifname), "discard"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_DISCARDS",
                    )
                ),
            )
            if self.db_version < ConfigDBVersion("version_4_0_0"):
                self.metric_interface_receive_error_input_packets.add_metric(
                    [self.get_additional_info(ifname), "drop"],
                    floatify(
                        self.getFromDB(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IN_DROPPED_PKTS",
                        )
                    ),
                )
            self.metric_interface_receive_error_input_packets.add_metric(
                [self.get_additional_info(ifname), "pause"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_RX_PKTS",
                    )
                ),
            )
            # TX
            self.metric_interface_transmitted_bytes.add_metric(
                [self.get_additional_info(ifname)],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_OCTETS",
                    )
                ),
            )
            self.metric_interface_transmitted_packets.add_metric(
                [self.get_additional_info(ifname), "unicast"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                    )
                ),
            )
            self.metric_interface_transmitted_packets.add_metric(
                [self.get_additional_info(ifname), "multicast"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS",
                    )
                ),
            )
            self.metric_interface_transmitted_packets.add_metric(
                [self.get_additional_info(ifname), "broadcast"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS",
                    )
                ),
            )
            # SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS
            # TX Errors
            self.metric_interface_transmit_error_output_packets.add_metric(
                [self.get_additional_info(ifname), "error"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_ERRORS",
                    )
                ),
            )
            self.metric_interface_transmit_error_output_packets.add_metric(
                [self.get_additional_info(ifname), "discard"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_DISCARDS",
                    )
                ),
            )
            self.metric_interface_transmit_error_output_packets.add_metric(
                [self.get_additional_info(ifname), "pause"],
                floatify(
                    self.getFromDB(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_TX_PKTS",
                    )
                ),
            )
            self.logger.debug("export_intf_counter :: ifname={}".format(ifname))
            try:
                port_table_key = SONiCCollector.get_port_table_key(ifname)
                is_operational = _decode(
                    self.getFromDB(self.sonic_db.APPL_DB, port_table_key, "oper_status")
                )
                last_flapped_seconds = to_timestamp(
                    floatify(
                        _decode(
                            self.getFromDB(
                                self.sonic_db.APPL_DB,
                                port_table_key,
                                "oper_status_change_uptime",
                            )
                        )
                    )
                )
                is_admin = self.get_portinfo(ifname, "admin_status")
                self.metric_interface_operational_status.add_metric(
                    [self.get_additional_info(ifname)], boolify(is_operational)
                )
                self.metric_interface_admin_status.add_metric(
                    [self.get_additional_info(ifname)], boolify(is_admin)
                )
                self.metric_interface_last_flapped_seconds.add_metric(
                    [self.get_additional_info(ifname)], floatify(last_flapped_seconds)
                )
            except ValueError:
                pass

    def export_interface_queue_counters(self):
        maps = self.getAllFromDB(self.sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            decoded_counter_key = _decode(maps[ifname])
            counter_key = SONiCCollector.get_counter_key(decoded_counter_key)
            packet_type = _decode(
                self.getFromDB(
                    self.sonic_db.COUNTERS_DB,
                    COUNTER_QUEUE_TYPE_MAP,
                    decoded_counter_key,
                )
            )
            ifname = _decode(ifname)
            packets = self.getFromDB(
                self.sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_PACKETS",
            )
            bytes = self.getFromDB(
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
            self.logger.debug(
                "export_intf_queue_counters :: ifname={}, queue_type={}, packets={}".format(
                    ifname, queue_type, packets
                )
            )
            self.logger.debug(
                "export_intf_queue_counters :: ifname={}, queue_type={}, bytes={}".format(
                    ifname, queue_type, bytes
                )
            )
            self.metric_interface_queue_processed_packets.add_metric(
                [self.get_additional_info(ifname), queue, queue_type], floatify(packets)
            )
            self.metric_interface_queue_processed_bytes.add_metric(
                [self.get_additional_info(ifname), queue, queue_type], floatify(bytes)
            )

    def export_interface_optic_data(self):
        keys = self.getKeysFromDB(
            self.sonic_db.STATE_DB, TRANSCEIVER_DOM_SENSOR_PATTERN
        )
        self.logger.debug("export_interface_optic_data :: keys={}".format(keys))

        if not keys:
            return
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_DOM_SENSOR, "")
            transceiver_sensor_data = self.getAllFromDB(self.sonic_db.STATE_DB, key)

            vcchighalarm = (
                vcchighwarning
            ) = (
                vcclowalarm
            ) = (
                vcclowwarning
            ) = (
                temphighalarm
            ) = (
                temphighwarning
            ) = (
                templowalarm
            ) = (
                templowwarning
            ) = (
                txbiashighalarm
            ) = (
                txbiashighwarning
            ) = (
                txbiaslowalarm
            ) = (
                txbiaslowwarning
            ) = (
                txpowerhighalarm
            ) = (
                txpowerhighwarning
            ) = (
                txpowerlowalarm
            ) = (
                txpowerlowwarning
            ) = (
                rxpowerhighalarm
            ) = rxpowerhighwarning = rxpowerlowalarm = rxpowerlowwarning = "none"
            for measure in transceiver_sensor_data:
                measure_dec = _decode(measure)
                try:
                    value = transceiver_sensor_data[measure_dec]
                    match measure_dec:
                        case "voltage":
                            self.metric_interface_optic_volts.add_metric(
                                [ifname, self.get_additional_info(ifname)],
                                floatify(value),
                            )
                        case "vcchighalarm":
                            vcchighalarm = str(value)
                        case "vcchighwarning":
                            vcchighwarning = str(value)
                        case "vcclowalarm":
                            vcclowalarm = str(value)
                        case "vcclowwarning":
                            vcclowwarning = str(value)
                        case "temphighalarm":
                            temphighalarm = str(value)
                        case "temphighwarning":
                            temphighwarning = str(value)
                        case "templowalarm":
                            templowalarm = str(value)
                        case "templowwarning":
                            templowwarning = str(value)
                        case "txbiashighalarm":
                            txbiashighalarm = str(value)
                        case "txbiashighwarning":
                            txbiashighwarning = str(value)
                        case "txbiaslowalarm":
                            txbiaslowalarm = str(value)
                        case "txbiaslowwarning":
                            txbiaslowwarning = str(value)
                        case "txpowerhighalarm":
                            txpowerhighalarm = str(value)
                        case "txpowerhighwarning":
                            txpowerhighwarning = str(value)
                        case "txpowerlowalarm":
                            txpowerlowalarm = str(value)
                        case "txpowerlowwarning":
                            txpowerlowwarning = str(value)
                        case "rxpowerhighalarm":
                            rxpowerhighalarm = str(value)
                        case "rxpowerhighwarning":
                            rxpowerhighwarning = str(value)
                        case "rxpowerlowalarm":
                            rxpowerlowalarm = str(value)
                        case "rxpowerlowwarning":
                            rxpowerlowwarning = str(value)
                        case "temperature":
                            self.metric_interface_optic_celsius.add_metric(
                                [ifname, self.get_additional_info(ifname)],
                                floatify(value),
                            )
                        case _:
                            if match := self.rx_power_regex.fullmatch(measure_dec):
                                optic_unit = match.group(1)
                                self.metric_interface_receive_optic_power_dbm.add_metric(
                                    [
                                        ifname,
                                        self.get_additional_info(ifname),
                                        optic_unit,
                                    ],
                                    floatify(value),
                                )
                            elif match := self.tx_power_regex.fullmatch(measure_dec):
                                optic_unit = match.group(1)
                                self.metric_interface_transmit_optic_power_dbm.add_metric(
                                    [
                                        ifname,
                                        self.get_additional_info(ifname),
                                        optic_unit,
                                    ],
                                    floatify(value),
                                )
                            elif match := self.tx_bias_regex.fullmatch(measure_dec):
                                optic_unit = match.group(1)
                                # This resolves mA to Amperes
                                self.metric_interface_transmit_optic_bias_amperes.add_metric(
                                    [
                                        ifname,
                                        self.get_additional_info(ifname),
                                        optic_unit,
                                    ],
                                    floatify(value) / 1000,
                                )
                except ValueError as e:
                    pass

            self.metric_transceiver_threshold_info.add_metric(
                [
                    ifname,
                    self.get_additional_info(ifname),
                    vcchighalarm,
                    vcchighwarning,
                    vcclowalarm,
                    vcclowwarning,
                    temphighalarm,
                    temphighwarning,
                    templowalarm,
                    templowwarning,
                    txbiashighalarm,
                    txbiashighwarning,
                    txbiaslowalarm,
                    txbiaslowwarning,
                    txpowerhighalarm,
                    txpowerhighwarning,
                    txpowerlowalarm,
                    txpowerlowwarning,
                    rxpowerhighalarm,
                    rxpowerhighwarning,
                    rxpowerlowalarm,
                    rxpowerlowwarning,
                ],
                1,
            )

    def export_interface_cable_data(self):
        keys = self.getKeysFromDB(self.sonic_db.STATE_DB, TRANSCEIVER_INFO_PATTERN)
        if not keys:
            return
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_INFO, "")
            cable_type = ""
            if self.db_version < ConfigDBVersion("version_4_0_0"):
                cable_type = _decode(
                    str(
                        self.getFromDB(self.sonic_db.STATE_DB, key, "Connector")
                    ).lower()
                )
            else:
                cable_type = _decode(
                    str(
                        self.getFromDB(self.sonic_db.STATE_DB, key, "connector")
                    ).lower()
                )
            connector_type = _decode(
                str(self.getFromDB(self.sonic_db.STATE_DB, key, "connector_type"))
            ).lower()
            serial = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "vendor_serial_number")
            )
            part_number = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "vendor_part_number")
            )
            revision = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "vendor_revision")
            )
            form_factor = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "form_factor")
            ).lower()
            display_name = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "display_name")
            )
            media_interface = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "media_interface")
            ).lower()
            try:
                cable_len = floatify(
                    self.getFromDB(self.sonic_db.STATE_DB, key, "cable_length")
                )
                self.metric_interface_cable_length_meters.add_metric(
                    [self.get_additional_info(ifname), cable_type, connector_type],
                    cable_len,
                )
            except ValueError:
                pass
            self.logger.debug(
                f"export_interface_cable_data :: interface={self.get_additional_info(ifname)}"
            )
            self.metric_interface_transceiver_info.add_metric(
                [
                    self.get_additional_info(ifname),
                    serial,
                    part_number,
                    revision,
                    form_factor,
                    connector_type,
                    display_name,
                    media_interface,
                ],
                1,
            )

    def export_psu_info(self):
        keys = self.getKeysFromDB(self.sonic_db.STATE_DB, PSU_INFO_PATTERN)
        if not keys:
            return
        for key in keys:
            serial = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "serial")
            ).strip()
            available_status = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "presence")
            )
            operational_status = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "status")
            )
            model = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, key, "model")
            ).strip()
            model_name = _decode(self.getFromDB(self.sonic_db.STATE_DB, key, "name"))
            _, slot = _decode(key.replace(PSU_INFO, "")).lower().split(" ")
            try:
                in_volts = floatify(
                    self.getFromDB(self.sonic_db.STATE_DB, key, "input_voltage")
                )
                in_amperes = floatify(
                    self.getFromDB(self.sonic_db.STATE_DB, key, "input_current")
                )
                self.metric_device_psu_input_amperes.add_metric([slot], in_amperes)
                self.metric_device_psu_input_volts.add_metric([slot], in_volts)
                self.logger.debug(
                    f"export_psu_info :: slot={slot}, in_amperes={in_amperes}, in_volts={in_volts}"
                )
            except ValueError:
                pass
            try:
                out_volts = floatify(
                    self.getFromDB(self.sonic_db.STATE_DB, key, "output_voltage")
                )
                out_amperes = floatify(
                    self.getFromDB(self.sonic_db.STATE_DB, key, "output_current")
                )
                self.metric_device_psu_output_amperes.add_metric([slot], out_amperes)
                self.metric_device_psu_output_volts.add_metric([slot], out_volts)
                self.logger.debug(
                    f"export_psu_info :: slot={slot}, out_amperes={out_amperes}, out_volts={out_volts}"
                )
            except ValueError:
                pass
            try:
                temperature = float("-Inf")
                if self.db_version < ConfigDBVersion("version_4_0_0"):
                    temperature = floatify(
                        self.getFromDB(self.sonic_db.STATE_DB, key, "temperature")
                    )
                else:
                    temperature = floatify(
                        self.getFromDB(self.sonic_db.STATE_DB, key, "temp")
                    )
                self.metric_device_psu_celsius.add_metric([slot], temperature)
            except ValueError:
                pass
            self.metric_device_psu_available_status.add_metric(
                [slot], boolify(available_status)
            )
            self.metric_device_psu_operational_status.add_metric(
                [slot], boolify(operational_status)
            )
            self.metric_device_psu_info.add_metric([slot, serial, model_name, model], 1)

    def export_fan_info(self):
        keys = self.getKeysFromDB(self.sonic_db.STATE_DB, FAN_INFO_PATTERN)
        if not keys:
            return
        for key in keys:
            try:
                fullname = _decode(self.getFromDB(self.sonic_db.STATE_DB, key, "name"))
                rpm = floatify(self.getFromDB(self.sonic_db.STATE_DB, key, "speed"))
                is_operational = _decode(
                    self.getFromDB(self.sonic_db.STATE_DB, key, "status")
                )
                is_available = boolify(
                    _decode(self.getFromDB(self.sonic_db.STATE_DB, key, "presence"))
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
                                self.getFromDB(
                                    self.sonic_db.STATE_DB,
                                    f"{PSU_INFO}{name}",
                                    "status",
                                )
                            )
                        )
                self.metric_device_fan_rpm.add_metric([name, slot], rpm)
                self.metric_device_fan_operational_status.add_metric(
                    [name, slot], boolify(is_operational)
                )
                self.metric_device_fan_available_status.add_metric(
                    [name, slot], is_available
                )
                self.logger.debug(
                    f"export_fan_info :: fullname={fullname} oper={boolify(is_operational)}, presence={is_available}, rpm={rpm}"
                )
            except ValueError:
                pass

    def export_hwmon_temp_info(self, switch_model, air_flow):
        for name, sensor in self.sys_class_hwmon.sensors.items():
            try:
                last_two_bytes = sensor.address[-2:]
                name = TEMP_SENSORS[switch_model][air_flow][last_two_bytes]
            except (ValueError, KeyError, TypeError) as e:
                self.logger.debug(
                    f"export_hwmon_temp_info :: air_flow={air_flow}, switch_mode={switch_model} address={last_two_bytes}, e={e}"
                )
                continue

            for value in sensor.values:
                _, subvalue = value.name.split("_", maxsplit=1)
                self.logger.debug(
                    f"export_hwmon_temp_info :: name={name}, -> value={value}"
                )
                match subvalue:
                    case "max":
                        self.metric_device_threshold_sensor_celsius.add_metric(
                            [name, AlarmType.HIGH_ALARM.value], value.value
                        )
                    case "max_hyst":
                        self.metric_device_threshold_sensor_celsius.add_metric(
                            [name, AlarmType.HIGH_WARNING.value], value.value
                        )
                    case "input":
                        self.metric_device_sensor_celsius.add_metric(
                            [name], value.value
                        )

    def export_temp_info(self):
        keys = self.getKeysFromDB(self.sonic_db.STATE_DB, TEMPERATURE_INFO_PATTERN)
        need_additional_temp_info = False
        unknown_switch_model = False
        air_flow = None
        switch_model = None
        try:
            air_flow = AirFlow(self.product_name[-1])
            switch_model = SwitchModel(self.platform_name.lower())
        except ValueError as e:
            self.logger.debug(f"export_temp_info :: exception={e}")
            unknown_switch_model = True
            pass

        for key in keys or []:
            try:
                name = _decode(self.getFromDB(self.sonic_db.STATE_DB, key, "name"))
                if name.lower().startswith("temp"):
                    need_additional_temp_info = True
                last_two_bytes: str = name[-2:]
                if not unknown_switch_model:
                    name = TEMP_SENSORS[switch_model][air_flow].get(
                        last_two_bytes, name
                    )

                temp = floatify(
                    _decode(self.getFromDB(self.sonic_db.STATE_DB, key, "temperature"))
                )
                high_threshold = floatify(
                    _decode(
                        self.getFromDB(self.sonic_db.STATE_DB, key, "high_threshold")
                    )
                )
                self.metric_device_sensor_celsius.add_metric([name], temp)
                self.metric_device_threshold_sensor_celsius.add_metric(
                    [name, AlarmType.HIGH_ALARM.value], high_threshold
                )
                self.logger.debug(
                    f"export_temp_info :: name={name}, temp={temp}, high_threshold={high_threshold}"
                )
            except ValueError:
                pass

        if (not keys or need_additional_temp_info) and not unknown_switch_model:
            self.export_hwmon_temp_info(switch_model, air_flow)

    def export_system_info(self):
        self.metric_device_uptime.add_metric([], get_uptime().total_seconds())
        for chassis_raw, data in self.chassis.items():
            chassis = chassis_raw
            if match := self.chassis_slot_regex.fullmatch(chassis_raw):
                chassis = match.group(1)
            part_number = _decode(data.get("part_num", ""))
            serial_number = _decode(data.get("serial_num", ""))
            mac_address = _decode(data.get("base_mac_addr", ""))
            onie_version = _decode(data.get("onie_version", ""))
            software_version = _decode(
                self.getFromDB(self.sonic_db.STATE_DB, "IMAGE_GLOBAL|config", "current")
            )
            platform_name = _decode(data.get("platform_name", ""))
            hardware_revision = _decode(data.get("hardware_revision", ""))
            product_name = _decode(data.get("product_name", ""))
            self.metric_device_info.add_metric(
                [
                    chassis,
                    platform_name,
                    part_number,
                    serial_number,
                    mac_address,
                    software_version,
                    onie_version,
                    hardware_revision,
                    product_name,
                ],
                1,
            )
            self.logger.debug(
                "export_sys_info :: part_num={}, serial_num={}, mac_addr={}, software_version={}".format(
                    part_number, serial_number, mac_address, software_version
                )
            )
        keys = self.getKeysFromDB(self.sonic_db.STATE_DB, PROCESS_STATS_PATTERN)
        cpu_memory_usages = [
            (
                floatify(_decode(self.getFromDB(self.sonic_db.STATE_DB, key, "%CPU"))),
                floatify(_decode(self.getFromDB(self.sonic_db.STATE_DB, key, "%MEM"))),
            )
            for key in keys
            if not key.replace(PROCESS_STATS, "").lower() in PROCESS_STATS_IGNORE
        ]
        cpu_usage = sum(cpu_usage for cpu_usage, _ in cpu_memory_usages)
        memory_usage = sum(memory_usage for _, memory_usage in cpu_memory_usages)
        self.system_cpu_ratio.add_metric([], cpu_usage / 100)
        self.system_memory_ratio.add_metric([], memory_usage / 100)
        self.logger.debug(
            f"export_sys_info :: cpu_usage={cpu_usage}, memory_usage={memory_usage}"
        )

    def export_static_anycast_gateway_info(self):
        # SAG Static Anycast Gateway
        # Labels
        # gwip
        # VRF
        # VNI
        # interface
        # Metrics
        # admin_status /sys/class/net/<interface_name>/flags
        # oper_status /sys/class/net/<interface_name>/carrier

        exportable = {InternetProtocol.v4: False, InternetProtocol.v6: False}
        keys = self.getKeysFromDB(self.sonic_db.CONFIG_DB, SAG_PATTERN)
        if not list(keys):
            # break if no SAG is configured
            return
        global_data = self.getAllFromDB(self.sonic_db.CONFIG_DB, SAG_GLOBAL)
        vxlan_tunnel_map = self.getKeysFromDB(
            self.sonic_db.CONFIG_DB, VXLAN_TUNNEL_MAP_PATTERN
        )

        for internet_protocol in InternetProtocol:
            if global_data and boolify(global_data[internet_protocol.value].lower()):
                exportable[internet_protocol] = True
                self.metric_sag_info.add_metric(
                    [internet_protocol.value.lower(), _decode(global_data["gwmac"])], 1
                )

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
                        self.getFromDB(
                            self.sonic_db.CONFIG_DB,
                            f"{VLAN_INTERFACE}{interface}",
                            "vrf_name",
                        )
                    )
                    gateway_ip = _decode(
                        self.getFromDB(self.sonic_db.CONFIG_DB, key, "gwip@")
                    )
                    vni_key = next(
                        vxlan_tunnel_key
                        for vxlan_tunnel_key in vxlan_tunnel_map
                        if _decode(vxlan_tunnel_key).endswith(interface)
                    )
                    vni = _decode(
                        self.getFromDB(self.sonic_db.CONFIG_DB, vni_key, "vni")
                    )
                    self.metric_sag_admin_status.add_metric(
                        [interface, vrf, gateway_ip, ip_family.value.lower(), str(vni)],
                        self.sys_class_net.admin_enabled(interface),
                    )
                    self.metric_sag_operational_status.add_metric(
                        [interface, vrf, gateway_ip, ip_family.value.lower(), str(vni)],
                        self.sys_class_net.operational(interface),
                    )
                except (KeyError, StopIteration, OSError):
                    self.logger.debug(
                        f"export_static_anycast_gateway_info :: No Static Anycast Gateway for interface={interface}"
                    )
                    pass

    def export_bgp_info(self):
        # vtysh -c "show bgp vrf all ipv4 unicast summary json"
        # vtysh -c "show bgp vrf all ipv6 unicast summary json"
        # vtysh -c "show bgp vrf all l2vpn evpn summary json"
        # vtysh -c "show bgp vrf all summary json"
        #
        # BGP Peerings
        ##
        # Labels
        # peer_type = ipv4/ipv6
        # vrf = vrf_namen
        # neighbor = dns namen / ip | hostname for servers
        # remote_as = as_nummer
        # bgp_protocol_type = evpn/ipv4/ipv6
        # Metrik
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
                    as_id = family_data.get("as")
                    for peername, peerdata in family_data["peers"].items():
                        # ["vrf", "peername", "neighbor", "peer_protocol", "protocol_family_advertised", "remote_as"]
                        bgp_lbl = [
                            vrf,
                            str(as_id),
                            peername,
                            peerdata.get("hostname", self.dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            self.vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ]
                        self.metric_bgp_uptime_seconds.add_metric(
                            [*bgp_lbl],
                            floatify(peerdata.get("peerUptimeMsec", 1000) / 1000),
                        )
                        self.metric_bgp_status.add_metric(
                            [*bgp_lbl], boolify(peerdata.get("state", ""))
                        )
                        self.metric_bgp_prefixes_received.add_metric(
                            [*bgp_lbl], floatify(peerdata.get("pfxRcd", 0))
                        )
                        self.metric_bgp_prefixes_transmitted.add_metric(
                            [*bgp_lbl], floatify(peerdata.get("pfxSnt", 0))
                        )
                        self.metric_bgp_messages_received.add_metric(
                            [*bgp_lbl], floatify(peerdata.get("msgRcvd", 0))
                        )
                        self.metric_bgp_messages_transmitted.add_metric(
                            [*bgp_lbl], floatify(peerdata.get("msgSent", 0))
                        )
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
                    self.metric_evpn_l2_vnis.add_metric(
                        [vni, interface, svi, layer.value, vrf],
                        floatify(len(evpn_vni["l2Vnis"])),
                    )
                case OSILayer.L2:
                    interface = _decode(evpn_vni["vxlanInterface"])
                    state = self.sys_class_net.operational(interface)
                    self.metric_evpn_remote_vteps.add_metric(
                        [vni, interface, svi, layer.value, vrf],
                        floatify(len(evpn_vni.get("numRemoteVteps", []))),
                    )
                    self.metric_evpn_arps.add_metric(
                        [vni, interface, svi, layer.value, vrf], evpn_vni["numArpNd"]
                    )
                    self.metric_evpn_mac_addresses.add_metric(
                        [vni, interface, svi, layer.value, vrf],
                        floatify(evpn_vni["numMacs"]),
                    )
            self.metric_evpn_status.add_metric(
                [vni, interface, svi, layer.value, vrf], boolify(state)
            )

    def export_ntp_global(self):
        dict = self.getAllFromDB(self.sonic_db.CONFIG_DB, "NTP|global")
        if dict:
            self.metric_ntp_global.add_metric(
                [
                    dict.get("vrf") if "vrf" in dict else "",
                    dict.get("auth_enabled") if "auth_enabled" in dict else "",
                    dict.get("src_intf@") if "src_intf@" in dict else "",
                    dict.get("trusted_key@") if "trusted_key@" in dict else "",
                ],
                1,
            )

    def export_ntp_server(self):
        for key in self.getKeysFromDB(self.sonic_db.CONFIG_DB, NTP_SERVER_PATTERN):
            dict = self.getAllFromDB(self.sonic_db.CONFIG_DB, key)
            if dict:
                self.metric_ntp_server.add_metric(
                    [
                        key.split("|")[1],
                        dict.get("key_id") if "key_id" in dict else "",
                        dict.get("minpoll") if "minpoll" in dict else "",
                        dict.get("maxpoll") if "maxpoll" in dict else "",
                    ],
                    1,
                )

    def export_ntp_peers(self):
        vrf = self.getFromDB(
            self.sonic_db.CONFIG_DB, "NTP|global", "vrf", retries=0, timeout=0
        )
        peers = self.ntpq.get_peers(vrf=vrf)
        ntp_rv = self.ntpq.get_rv(vrf=vrf)
        ntp_status = ntp_rv.get("associd", "")
        if "leap_none" in ntp_status:
            self.metric_ntp_sync_status.add_metric([], 1.0)
        else:
            self.metric_ntp_sync_status.add_metric([], 0)
        self.logger.debug(f"hello {json.dumps(peers, indent=2)}")
        for op in peers:
            self.logger.debug(
                f"export_ntp_peers :: {' '.join([f'{key}={value}' for key, value in op.items()])}"
            )
            self.metric_ntp_peers.add_metric(
                [
                    op.get("remote"),
                    op.get("refid"),
                    str(op.get("st")),
                    op.get("t"),
                    str(op.get("poll")),
                    str(op.get("reach")),
                    " " if op.get("state") is None else op.get("state"),
                ],
                1,
            )
            self.metric_ntp_jitter.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("jitter"))
            )
            self.metric_ntp_offset.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("offset"))
            )
            self.metric_ntp_rtd.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("delay"))
            )
            self.metric_ntp_when.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("when"))
            )

    def export_sys_status(self):
        sts, sts_core = self.is_sonic_sys_ready()
        self.metric_sys_status.add_metric(
            [str(sts), str(sts_core)], floatify(sts & sts_core)
        )

    def export_mclag_domain(self):
        mclag_domain = {
            _decode(key).replace(MCLAG_DOMAIN, ""): self.getAllFromDB(
                self.sonic_db.CONFIG_DB, key
            )
            for key in self.getKeysFromDB(self.sonic_db.CONFIG_DB, MCLAG_DOMAIN_PATTERN)
        }
        if mclag_domain and mclag_domain is not None:
            for domain_id, domain_attr in mclag_domain.items():
                source_ip = domain_attr.get("source_ip", "")
                keepalive_interval = domain_attr.get("keepalive_interval", "")
                session_timeout = domain_attr.get("session_timeout", "")
                peer_ip = domain_attr.get("peer_ip", "")
                peer_link = domain_attr.get("peer_link", "")
                mclag_system_mac = domain_attr.get("mclag_system_mac", "")
                self.metric_mclag_domain.add_metric(
                    [
                        domain_id,
                        "" if not source_ip else source_ip,
                        "" if not keepalive_interval else str(keepalive_interval),
                        "" if not session_timeout else str(session_timeout),
                        "" if not peer_ip else peer_ip,
                        "" if not peer_link else peer_link,
                        "" if not mclag_system_mac else mclag_system_mac,
                    ],
                    1,
                )

    def export_mclag_oper_state(self):
        mclag_state = {
            _decode(key).replace(MCLAG_TABLE, ""): self.getAllFromDB(
                self.sonic_db.STATE_DB, key
            )
            for key in self.getKeysFromDB(self.sonic_db.STATE_DB, MCLAG_TABLE_PATTERN)
        }
        if mclag_state and mclag_state is not None:
            for domain_id, domain_state_attr in mclag_state.items():
                mclag_system_mac = domain_state_attr.get("mclag_system_mac", "")
                role = domain_state_attr.get("role", "")
                system_mac = domain_state_attr.get("system_mac", "")
                peer_mac = domain_state_attr.get("peer_mac", "")
                oper_status = (
                    1 if domain_state_attr.get("oper_status", "") == "up" else 0
                )
                reason = domain_state_attr.get("reason", "")
                self.metric_mclag_oper_state.add_metric(
                    [
                        domain_id,
                        "" if not mclag_system_mac else mclag_system_mac,
                        "" if not role else role,
                        "" if not system_mac else system_mac,
                        "" if not peer_mac else peer_mac,
                        "" if not reason else reason,
                    ],
                    oper_status,
                )

    def export_crm(self):
        try:
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:LAG"
            )
            self.crm_acl_stats_egress_lag_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_egress_lag_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_egress_lag_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_egress_lag_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:PORT"
            )
            self.crm_acl_stats_egress_port_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_egress_port_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_egress_port_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_egress_port_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:RIF"
            )
            self.crm_acl_stats_egress_rif_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_egress_rif_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_egress_rif_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_egress_rif_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:SWITCH"
            )
            self.crm_acl_stats_egress_switch_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_egress_switch_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_egress_switch_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_egress_switch_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:VLAN"
            )
            self.crm_acl_stats_egress_vlan_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_egress_vlan_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_egress_vlan_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_egress_vlan_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )

            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:LAG"
            )
            self.crm_acl_stats_ingress_lag_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_ingress_lag_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_ingress_lag_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_ingress_lag_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:PORT"
            )
            self.crm_acl_stats_ingress_port_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_ingress_port_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_ingress_port_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_ingress_port_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:RIF"
            )
            self.crm_acl_stats_ingress_rif_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_ingress_rif_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_ingress_rif_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_ingress_rif_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:SWITCH"
            )
            self.crm_acl_stats_ingress_switch_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_ingress_switch_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_ingress_switch_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_ingress_switch_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )
            out_put = self.getAllFromDB(
                self.sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:VLAN"
            )
            self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_used.add_metric(
                [], out_put.get("crm_stats_acl_group_used",0)
            )
            self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_used.add_metric(
                [], out_put.get("crm_stats_acl_table_used",0)
            )
            self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_available.add_metric(
                [], out_put.get("crm_stats_acl_group_available",0)
            )
            self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_available.add_metric(
                [], out_put.get("crm_stats_acl_table_available",0)
            )

            out_put = self.getAllFromDB(self.sonic_db.COUNTERS_DB, "CRM:STATS")
            self.crm_stats_dnat_entry_used.add_metric(
                [], out_put.get("crm_stats_dnat_entry_used",0)
            )
            self.crm_stats_fdb_entry_used.add_metric(
                [], out_put.get("crm_stats_fdb_entry_used",0)
            )
            self.crm_stats_ipmc_entry_used.add_metric(
                [], out_put.get("crm_stats_ipmc_entry_used",0)
            )
            self.crm_stats_ipv4_neighbor_used.add_metric(
                [], out_put.get("crm_stats_ipv4_neighbor_used",0)
            )
            self.crm_stats_ipv4_nexthop_used.add_metric(
                [], out_put.get("crm_stats_ipv4_nexthop_used",0)
            )
            self.crm_stats_ipv4_route_used.add_metric(
                [], out_put.get("crm_stats_ipv4_route_used",0)
            )
            self.crm_stats_ipv6_neighbor_used.add_metric(
                [], out_put.get("crm_stats_ipv6_neighbor_used",0)
            )
            self.crm_stats_ipv6_nexthop_used.add_metric(
                [], out_put.get("crm_stats_ipv6_nexthop_used",0)
            )
            self.crm_stats_ipv6_route_used.add_metric(
                [], out_put.get("crm_stats_ipv6_route_used",0)
            )
            self.crm_stats_nexthop_group_member_used.add_metric(
                [], out_put.get("crm_stats_nexthop_group_member_used",0)
            )
            self.crm_stats_nexthop_group_used.add_metric(
                [], out_put.get("crm_stats_nexthop_group_used",0)
            )
            self.crm_stats_snat_entry_used.add_metric(
                [], out_put.get("crm_stats_snat_entry_used",0)
            )
            self.crm_stats_dnat_entry_available.add_metric(
                [], out_put.get("crm_stats_dnat_entry_available",0)
            )
            self.crm_stats_fdb_entry_available.add_metric(
                [], out_put.get("crm_stats_fdb_entry_available",0)
            )
            self.crm_stats_ipmc_entry_available.add_metric(
                [], out_put.get("crm_stats_ipmc_entry_available",0)
            )
            self.crm_stats_ipv4_neighbor_available.add_metric(
                [], out_put.get("crm_stats_ipv4_neighbor_available",0)
            )
            self.crm_stats_ipv4_nexthop_available.add_metric(
                [], out_put.get("crm_stats_ipv4_nexthop_available",0)
            )
            self.crm_stats_ipv4_route_available.add_metric(
                [], out_put.get("crm_stats_ipv4_route_available",0)
            )
            self.crm_stats_ipv6_neighbor_available.add_metric(
                [], out_put.get("crm_stats_ipv6_neighbor_available",0)
            )
            self.crm_stats_ipv6_nexthop_available.add_metric(
                [], out_put.get("crm_stats_ipv6_nexthop_available",0)
            )
            self.crm_stats_ipv6_route_available.add_metric(
                [], out_put.get("crm_stats_ipv6_route_available",0)
            )
            self.crm_stats_nexthop_group_available.add_metric(
                [], out_put.get("crm_stats_nexthop_group_available",0)
            )
            self.crm_stats_nexthop_group_member_available.add_metric(
                [], out_put.get("crm_stats_nexthop_group_member_available",0)
            )
            self.crm_stats_snat_entry_available.add_metric(
                [], out_put.get("crm_stats_snat_entry_available",0)
            )

        except Exception as e:
            logging.info(e)

    def collect(self):
        try:
            self._init_metrics()
            date_time = datetime.now()
            wait(
                [
                    self.thread_pool.submit(self.export_crm),
                    self.thread_pool.submit(self.export_mclag_oper_state),
                    self.thread_pool.submit(self.export_mclag_domain),
                    self.thread_pool.submit(self.export_interface_counters),
                    self.thread_pool.submit(self.export_interface_queue_counters),
                    self.thread_pool.submit(self.export_interface_cable_data),
                    self.thread_pool.submit(self.export_interface_optic_data),
                    self.thread_pool.submit(self.export_system_info),
                    self.thread_pool.submit(self.export_psu_info),
                    self.thread_pool.submit(self.export_fan_info),
                    self.thread_pool.submit(self.export_temp_info),
                    self.thread_pool.submit(self.export_vxlan_tunnel_info),
                    self.thread_pool.submit(self.export_bgp_info),
                    self.thread_pool.submit(self.export_evpn_vni_info),
                    self.thread_pool.submit(self.export_static_anycast_gateway_info),
                    self.thread_pool.submit(self.export_ntp_peers),
                    self.thread_pool.submit(self.export_ntp_global),
                    self.thread_pool.submit(self.export_ntp_server),
                    self.thread_pool.submit(self.export_sys_status),
                ],
                return_when=ALL_COMPLETED,
            )

            self.logger.debug(
                f"Time taken in metrics collection {datetime.now() - date_time}"
            )

            yield self.crm_acl_stats_egress_lag_crm_stats_acl_group_used
            yield self.crm_acl_stats_egress_lag_crm_stats_acl_table_used
            yield self.crm_acl_stats_egress_lag_crm_stats_acl_group_available
            yield self.crm_acl_stats_egress_lag_crm_stats_acl_table_available
            yield self.crm_acl_stats_egress_port_crm_stats_acl_group_used
            yield self.crm_acl_stats_egress_port_crm_stats_acl_table_used
            yield self.crm_acl_stats_egress_port_crm_stats_acl_group_available
            yield self.crm_acl_stats_egress_port_crm_stats_acl_table_available
            yield self.crm_acl_stats_egress_rif_crm_stats_acl_group_used
            yield self.crm_acl_stats_egress_rif_crm_stats_acl_table_used
            yield self.crm_acl_stats_egress_rif_crm_stats_acl_group_available
            yield self.crm_acl_stats_egress_rif_crm_stats_acl_table_available
            yield self.crm_acl_stats_egress_switch_crm_stats_acl_group_used
            yield self.crm_acl_stats_egress_switch_crm_stats_acl_table_used
            yield self.crm_acl_stats_egress_switch_crm_stats_acl_group_available
            yield self.crm_acl_stats_egress_switch_crm_stats_acl_table_available
            yield self.crm_acl_stats_egress_vlan_crm_stats_acl_group_used
            yield self.crm_acl_stats_egress_vlan_crm_stats_acl_table_used
            yield self.crm_acl_stats_egress_vlan_crm_stats_acl_group_available
            yield self.crm_acl_stats_egress_vlan_crm_stats_acl_table_available
            yield self.crm_acl_stats_ingress_lag_crm_stats_acl_group_used
            yield self.crm_acl_stats_ingress_lag_crm_stats_acl_table_used
            yield self.crm_acl_stats_ingress_lag_crm_stats_acl_group_available
            yield self.crm_acl_stats_ingress_lag_crm_stats_acl_table_available
            yield self.crm_acl_stats_ingress_port_crm_stats_acl_group_used
            yield self.crm_acl_stats_ingress_port_crm_stats_acl_table_used
            yield self.crm_acl_stats_ingress_port_crm_stats_acl_group_available
            yield self.crm_acl_stats_ingress_port_crm_stats_acl_table_available
            yield self.crm_acl_stats_ingress_rif_crm_stats_acl_group_used
            yield self.crm_acl_stats_ingress_rif_crm_stats_acl_table_used
            yield self.crm_acl_stats_ingress_rif_crm_stats_acl_group_available
            yield self.crm_acl_stats_ingress_rif_crm_stats_acl_table_available
            yield self.crm_acl_stats_ingress_switch_crm_stats_acl_group_used
            yield self.crm_acl_stats_ingress_switch_crm_stats_acl_table_used
            yield self.crm_acl_stats_ingress_switch_crm_stats_acl_group_available
            yield self.crm_acl_stats_ingress_switch_crm_stats_acl_table_available
            yield self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_used
            yield self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_used
            yield self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_available
            yield self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_available
            yield self.crm_stats_dnat_entry_used
            yield self.crm_stats_fdb_entry_used
            yield self.crm_stats_ipmc_entry_used
            yield self.crm_stats_ipv4_neighbor_used
            yield self.crm_stats_ipv4_nexthop_used
            yield self.crm_stats_ipv4_route_used
            yield self.crm_stats_ipv6_neighbor_used
            yield self.crm_stats_ipv6_nexthop_used
            yield self.crm_stats_ipv6_route_used
            yield self.crm_stats_nexthop_group_member_used
            yield self.crm_stats_nexthop_group_used
            yield self.crm_stats_snat_entry_used
            yield self.crm_stats_dnat_entry_available
            yield self.crm_stats_fdb_entry_available
            yield self.crm_stats_ipmc_entry_available
            yield self.crm_stats_ipv4_neighbor_available
            yield self.crm_stats_ipv4_nexthop_available
            yield self.crm_stats_ipv4_route_available
            yield self.crm_stats_ipv6_neighbor_available
            yield self.crm_stats_ipv6_nexthop_available
            yield self.crm_stats_ipv6_route_available
            yield self.crm_stats_nexthop_group_available
            yield self.crm_stats_nexthop_group_member_available
            yield self.crm_stats_snat_entry_available
            yield self.metric_mclag_domain
            yield self.metric_mclag_oper_state
            yield self.metric_sys_status
            yield self.metric_ntp_sync_status
            yield self.metric_ntp_jitter
            yield self.metric_ntp_offset
            yield self.metric_ntp_rtd
            yield self.metric_ntp_when
            yield self.metric_ntp_peers
            yield self.metric_ntp_global
            yield self.metric_ntp_server
            yield self.metric_interface_info
            yield self.metric_interface_speed
            yield self.metric_interface_transmitted_bytes
            yield self.metric_interface_received_bytes
            yield self.metric_interface_transmitted_packets
            yield self.metric_interface_received_packets
            yield self.metric_interface_receive_error_input_packets
            yield self.metric_interface_transmit_error_output_packets
            yield self.metric_interface_received_ethernet_packets
            yield self.metric_interface_transmitted_ethernet_packets
            yield self.metric_interface_operational_status
            yield self.metric_interface_admin_status
            yield self.metric_interface_last_flapped_seconds
            yield self.metric_interface_queue_processed_packets
            yield self.metric_interface_queue_processed_bytes
            yield self.metric_interface_receive_optic_power_dbm
            yield self.metric_interface_transmit_optic_power_dbm
            yield self.metric_interface_transmit_optic_bias_amperes
            yield self.metric_interface_optic_celsius
            yield self.metric_interface_optic_volts
            yield self.metric_transceiver_threshold_info
            yield self.metric_interface_transceiver_info
            yield self.metric_interface_cable_length_meters
            yield self.metric_device_psu_input_volts
            yield self.metric_device_psu_input_amperes
            yield self.metric_device_psu_output_volts
            yield self.metric_device_psu_output_amperes
            yield self.metric_device_psu_operational_status
            yield self.metric_device_psu_available_status
            yield self.metric_device_psu_celsius
            yield self.metric_device_psu_info
            yield self.metric_device_fan_rpm
            yield self.metric_device_fan_operational_status
            yield self.metric_device_fan_available_status
            yield self.metric_device_sensor_celsius
            yield self.metric_device_threshold_sensor_celsius
            yield self.metric_vxlan_operational_status
            yield self.metric_device_uptime
            yield self.metric_device_info
            yield self.system_memory_ratio
            yield self.system_cpu_ratio
            yield self.metric_bgp_uptime_seconds
            yield self.metric_bgp_status
            yield self.metric_bgp_prefixes_received
            yield self.metric_bgp_prefixes_transmitted
            yield self.metric_bgp_messages_received
            yield self.metric_bgp_messages_transmitted
            yield self.metric_sag_operational_status
            yield self.metric_sag_admin_status
            yield self.metric_sag_info
            yield self.metric_evpn_status
            yield self.metric_evpn_remote_vteps
            yield self.metric_evpn_l2_vnis
            yield self.metric_evpn_mac_addresses
            yield self.metric_evpn_arps
        except KeyboardInterrupt as e:
            raise e


def main():
    port = int(
        os.environ.get("SONIC_EXPORTER_PORT", 9101)
    )  # setting port static as 9101. if required map it to someother port of host by editing compose file.
    address = str(os.environ.get("SONIC_EXPORTER_ADDRESS", "localhost"))
    logging_config_path = os.environ.get(
        "SONIC_EXPORTER_LOGGING_CONFIG", (BASE_PATH / "./config/logging.yml").resolve()
    )
    LOGGING_CONFIG_RAW = ""
    with open(logging_config_path, "r") as file:
        LOGGING_CONFIG_RAW = file.read()
    loglevel = os.environ.get("SONIC_EXPORTER_LOGLEVEL", None)
    LOGGING_CONFIG = yaml.safe_load(LOGGING_CONFIG_RAW)
    if (
        loglevel
        and "handlers" in LOGGING_CONFIG
        and "console" in LOGGING_CONFIG["handlers"]
        and "level" in LOGGING_CONFIG["handlers"]["console"]
    ):
        LOGGING_CONFIG["handlers"]["console"]["level"] = loglevel
    logging.config.dictConfig(LOGGING_CONFIG)
    logging.info("Starting Python exporter server at {}:{}".format(address, port))
    # TODO ip address validation
    prom.start_http_server(port, addr=address)
    classe = SONiCCollector
    classe.logger = logging.getLogger("__name__")
    sonic_collector = classe(
        os.environ.get("DEVELOPER_MODE", "False").lower() in TRUE_VALUES
    )
    REGISTRY.register(sonic_collector)
    while True:
        time.sleep(10**8)


def cli():
    try:
        file_path = os.path.dirname(__file__)
        if file_path != "":
            os.chdir(file_path)
        main()
    except KeyboardInterrupt:
        sys.exit(0)
