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
import os
import logging
import logging.config
import yaml
import sys
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
from datetime import datetime

import prometheus_client as prom
from prometheus_client.core import REGISTRY
from bgp import export_bgp_info
from crm import export_crm
from evpn import export_evpn_vni_info
from fan import export_fan_info
from interface import export_interface_cable_data, export_interface_counters, export_interface_optic_data, export_interface_queue_counters
from mclag import export_mclag_domain, export_mclag_oper_state
from ntpq import export_ntp_global, export_ntp_peers, export_ntp_server
from psu import export_psu_info
from sag import export_static_anycast_gateway_info

from sonic_exporter.constants import (
    TRUE_VALUES,
)
from sonic_exporter.utilities import is_sonic_sys_ready
from system import export_sys_status, export_system_info, export_temp_info
from vxlan import export_vxlan_tunnel_info

BASE_PATH = Path(__file__).parent


_logger = logging.getLogger(__name__)


def check_sonic_ready():
    if not is_sonic_sys_ready(retries=15):
        _logger.error(
            "SONiC System isn't ready even after several retries, exiting sonic-exporter."
        )
        sys.exit(0)

    _logger.info("SONiC System is ready.")


developer_mode = os.environ.get("DEVELOPER_MODE", "False").lower() in TRUE_VALUES


class SONiCCollector(object):
    thread_pool = ThreadPoolExecutor(10)

    def collect(self):
        try:
            self._init_metrics()
            date_time = datetime.now()
            wait(
                [
                    self.thread_pool.submit(export_crm),
                    self.thread_pool.submit(export_mclag_oper_state),
                    self.thread_pool.submit(export_mclag_domain),
                    self.thread_pool.submit(export_interface_counters),
                    self.thread_pool.submit(export_interface_queue_counters),
                    self.thread_pool.submit(export_interface_cable_data),
                    self.thread_pool.submit(export_interface_optic_data),
                    self.thread_pool.submit(export_system_info),
                    self.thread_pool.submit(export_psu_info),
                    self.thread_pool.submit(export_fan_info),
                    self.thread_pool.submit(export_temp_info),
                    self.thread_pool.submit(export_vxlan_tunnel_info),
                    self.thread_pool.submit(export_bgp_info),
                    self.thread_pool.submit(export_evpn_vni_info),
                    self.thread_pool.submit(export_static_anycast_gateway_info),
                    self.thread_pool.submit(export_ntp_peers),
                    self.thread_pool.submit(export_ntp_global),
                    self.thread_pool.submit(export_ntp_server),
                    self.thread_pool.submit(export_sys_status),
                ],
                return_when=ALL_COMPLETED,
            )

            self.logger.debug(
                f"Time taken in metrics collection {datetime.now() - date_time}"
            )

            yield crm_acl_stats_egress_lag_crm_stats_acl_group_used
            yield crm_acl_stats_egress_lag_crm_stats_acl_table_used
            yield crm_acl_stats_egress_lag_crm_stats_acl_group_available
            yield crm_acl_stats_egress_lag_crm_stats_acl_table_available
            yield crm_acl_stats_egress_port_crm_stats_acl_group_used
            yield crm_acl_stats_egress_port_crm_stats_acl_table_used
            yield crm_acl_stats_egress_port_crm_stats_acl_group_available
            yield crm_acl_stats_egress_port_crm_stats_acl_table_available
            yield crm_acl_stats_egress_rif_crm_stats_acl_group_used
            yield crm_acl_stats_egress_rif_crm_stats_acl_table_used
            yield crm_acl_stats_egress_rif_crm_stats_acl_group_available
            yield crm_acl_stats_egress_rif_crm_stats_acl_table_available
            yield crm_acl_stats_egress_switch_crm_stats_acl_group_used
            yield crm_acl_stats_egress_switch_crm_stats_acl_table_used
            yield crm_acl_stats_egress_switch_crm_stats_acl_group_available
            yield crm_acl_stats_egress_switch_crm_stats_acl_table_available
            yield crm_acl_stats_egress_vlan_crm_stats_acl_group_used
            yield crm_acl_stats_egress_vlan_crm_stats_acl_table_used
            yield crm_acl_stats_egress_vlan_crm_stats_acl_group_available
            yield crm_acl_stats_egress_vlan_crm_stats_acl_table_available
            yield crm_acl_stats_ingress_lag_crm_stats_acl_group_used
            yield crm_acl_stats_ingress_lag_crm_stats_acl_table_used
            yield crm_acl_stats_ingress_lag_crm_stats_acl_group_available
            yield crm_acl_stats_ingress_lag_crm_stats_acl_table_available
            yield crm_acl_stats_ingress_port_crm_stats_acl_group_used
            yield crm_acl_stats_ingress_port_crm_stats_acl_table_used
            yield crm_acl_stats_ingress_port_crm_stats_acl_group_available
            yield crm_acl_stats_ingress_port_crm_stats_acl_table_available
            yield crm_acl_stats_ingress_rif_crm_stats_acl_group_used
            yield crm_acl_stats_ingress_rif_crm_stats_acl_table_used
            yield crm_acl_stats_ingress_rif_crm_stats_acl_group_available
            yield crm_acl_stats_ingress_rif_crm_stats_acl_table_available
            yield crm_acl_stats_ingress_switch_crm_stats_acl_group_used
            yield crm_acl_stats_ingress_switch_crm_stats_acl_table_used
            yield crm_acl_stats_ingress_switch_crm_stats_acl_group_available
            yield crm_acl_stats_ingress_switch_crm_stats_acl_table_available
            yield crm_acl_stats_ingress_vlan_crm_stats_acl_group_used
            yield crm_acl_stats_ingress_vlan_crm_stats_acl_table_used
            yield crm_acl_stats_ingress_vlan_crm_stats_acl_group_available
            yield crm_acl_stats_ingress_vlan_crm_stats_acl_table_available
            yield crm_stats_dnat_entry_used
            yield crm_stats_fdb_entry_used
            yield crm_stats_ipmc_entry_used
            yield crm_stats_ipv4_neighbor_used
            yield crm_stats_ipv4_nexthop_used
            yield crm_stats_ipv4_route_used
            yield crm_stats_ipv6_neighbor_used
            yield crm_stats_ipv6_nexthop_used
            yield crm_stats_ipv6_route_used
            yield crm_stats_nexthop_group_member_used
            yield crm_stats_nexthop_group_used
            yield crm_stats_snat_entry_used
            yield crm_stats_dnat_entry_available
            yield crm_stats_fdb_entry_available
            yield crm_stats_ipmc_entry_available
            yield crm_stats_ipv4_neighbor_available
            yield crm_stats_ipv4_nexthop_available
            yield crm_stats_ipv4_route_available
            yield crm_stats_ipv6_neighbor_available
            yield crm_stats_ipv6_nexthop_available
            yield crm_stats_ipv6_route_available
            yield crm_stats_nexthop_group_available
            yield crm_stats_nexthop_group_member_available
            yield crm_stats_snat_entry_available
            yield metric_mclag_domain
            yield metric_mclag_oper_state
            yield metric_sys_status
            yield metric_ntp_sync_status
            yield metric_ntp_jitter
            yield metric_ntp_offset
            yield metric_ntp_rtd
            yield metric_ntp_when
            yield metric_ntp_peers
            yield metric_ntp_global
            yield metric_ntp_server
            yield metric_interface_info
            yield metric_interface_speed
            yield metric_interface_transmitted_bytes
            yield metric_interface_received_bytes
            yield metric_interface_transmitted_packets
            yield metric_interface_received_packets
            yield metric_interface_receive_error_input_packets
            yield metric_interface_transmit_error_output_packets
            yield metric_interface_received_ethernet_packets
            yield metric_interface_transmitted_ethernet_packets
            yield metric_interface_operational_status
            yield metric_interface_admin_status
            yield metric_interface_last_flapped_seconds
            yield metric_interface_queue_processed_packets
            yield metric_interface_queue_processed_bytes
            yield metric_interface_receive_optic_power_dbm
            yield metric_interface_transmit_optic_power_dbm
            yield metric_interface_transmit_optic_bias_amperes
            yield metric_interface_optic_celsius
            yield metric_interface_optic_volts
            yield metric_transceiver_threshold_info
            yield metric_interface_transceiver_info
            yield metric_interface_cable_length_meters
            yield metric_device_psu_input_volts
            yield metric_device_psu_input_amperes
            yield metric_device_psu_output_volts
            yield metric_device_psu_output_amperes
            yield metric_device_psu_operational_status
            yield metric_device_psu_available_status
            yield metric_device_psu_celsius
            yield metric_device_psu_info
            yield metric_device_fan_rpm
            yield metric_device_fan_operational_status
            yield metric_device_fan_available_status
            yield metric_device_sensor_celsius
            yield metric_device_threshold_sensor_celsius
            yield metric_vxlan_operational_status
            yield metric_device_uptime
            yield metric_device_info
            yield system_memory_ratio
            yield system_cpu_ratio
            yield metric_bgp_uptime_seconds
            yield metric_bgp_status
            yield metric_bgp_prefixes_received
            yield metric_bgp_prefixes_transmitted
            yield metric_bgp_messages_received
            yield metric_bgp_messages_transmitted
            yield metric_sag_operational_status
            yield metric_sag_admin_status
            yield metric_sag_info
            yield metric_evpn_status
            yield metric_evpn_remote_vteps
            yield metric_evpn_l2_vnis
            yield metric_evpn_mac_addresses
            yield metric_evpn_arps
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
    sonic_collector = classe(developer_mode)
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
