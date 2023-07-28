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

import logging
from prometheus_client.core import GaugeMetricFamily
from .db_util import getAllFromDB
from .db_util import sonic_db

_logger = logging.getLogger(__name__)
crm_acl_stats_egress_lag_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_egress_lag_crm_stats_acl_group_used",
    "crm_acl_stats_egress_lag_crm_stats_acl_group_used",
)
crm_acl_stats_egress_lag_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_egress_lag_crm_stats_acl_table_used",
    "crm_acl_stats_egress_lag_crm_stats_acl_table_used",
)
crm_acl_stats_egress_lag_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_egress_lag_crm_stats_acl_group_available",
    "crm_acl_stats_egress_lag_crm_stats_acl_group_available",
)
crm_acl_stats_egress_lag_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_egress_lag_crm_stats_acl_table_available",
    "crm_acl_stats_egress_lag_crm_stats_acl_table_available",
)

crm_acl_stats_egress_port_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_egress_port_crm_stats_acl_group_used",
    "crm_acl_stats_egress_port_crm_stats_acl_group_used",
)
crm_acl_stats_egress_port_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_egress_port_crm_stats_acl_table_used",
    "crm_acl_stats_egress_port_crm_stats_acl_table_used",
)
crm_acl_stats_egress_port_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_egress_port_crm_stats_acl_group_available",
    "crm_acl_stats_egress_port_crm_stats_acl_group_available",
)
crm_acl_stats_egress_port_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_egress_port_crm_stats_acl_table_available",
    "crm_acl_stats_egress_port_crm_stats_acl_table_available",
)

crm_acl_stats_egress_rif_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_egress_rif_crm_stats_acl_group_used",
    "crm_acl_stats_egress_rif_crm_stats_acl_group_used",
)
crm_acl_stats_egress_rif_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_egress_rif_crm_stats_acl_table_used",
    "crm_acl_stats_egress_rif_crm_stats_acl_table_used",
)
crm_acl_stats_egress_rif_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_egress_rif_crm_stats_acl_group_available",
    "crm_acl_stats_egress_rif_crm_stats_acl_group_available",
)
crm_acl_stats_egress_rif_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_egress_rif_crm_stats_acl_table_available",
    "crm_acl_stats_egress_rif_crm_stats_acl_table_available",
)

crm_acl_stats_egress_switch_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_egress_switch_crm_stats_acl_group_used",
    "crm_acl_stats_egress_switch_crm_stats_acl_group_used",
)
crm_acl_stats_egress_switch_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_egress_switch_crm_stats_acl_table_used",
    "crm_acl_stats_egress_switch_crm_stats_acl_table_used",
)
crm_acl_stats_egress_switch_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_egress_switch_crm_stats_acl_group_available",
    "crm_acl_stats_egress_switch_crm_stats_acl_group_available",
)
crm_acl_stats_egress_switch_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_egress_switch_crm_stats_acl_table_available",
    "crm_acl_stats_egress_switch_crm_stats_acl_table_available",
)

crm_acl_stats_egress_vlan_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_egress_vlan_crm_stats_acl_group_used",
    "crm_acl_stats_egress_vlan_crm_stats_acl_group_used",
)
crm_acl_stats_egress_vlan_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_egress_vlan_crm_stats_acl_table_used",
    "crm_acl_stats_egress_vlan_crm_stats_acl_table_used",
)
crm_acl_stats_egress_vlan_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_egress_vlan_crm_stats_acl_group_available",
    "crm_acl_stats_egress_vlan_crm_stats_acl_group_available",
)
crm_acl_stats_egress_vlan_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_egress_vlan_crm_stats_acl_table_available",
    "crm_acl_stats_egress_vlan_crm_stats_acl_table_available",
)

crm_acl_stats_ingress_lag_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_lag_crm_stats_acl_group_used",
    "crm_acl_stats_ingress_lag_crm_stats_acl_group_used",
)
crm_acl_stats_ingress_lag_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_lag_crm_stats_acl_table_used",
    "crm_acl_stats_ingress_lag_crm_stats_acl_table_used",
)
crm_acl_stats_ingress_lag_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_lag_crm_stats_acl_group_available",
    "crm_acl_stats_ingress_lag_crm_stats_acl_group_available",
)
crm_acl_stats_ingress_lag_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_lag_crm_stats_acl_table_available",
    "crm_acl_stats_ingress_lag_crm_stats_acl_table_available",
)

crm_acl_stats_ingress_port_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_port_crm_stats_acl_group_used",
    "crm_acl_stats_ingress_port_crm_stats_acl_group_used",
)
crm_acl_stats_ingress_port_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_port_crm_stats_acl_table_used",
    "crm_acl_stats_ingress_port_crm_stats_acl_table_used",
)
crm_acl_stats_ingress_port_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_port_crm_stats_acl_group_available",
    "crm_acl_stats_ingress_port_crm_stats_acl_group_available",
)
crm_acl_stats_ingress_port_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_port_crm_stats_acl_table_available",
    "crm_acl_stats_ingress_port_crm_stats_acl_table_available",
)

crm_acl_stats_ingress_rif_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_rif_crm_stats_acl_group_used",
    "crm_acl_stats_ingress_rif_crm_stats_acl_group_used",
)
crm_acl_stats_ingress_rif_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_rif_crm_stats_acl_table_used",
    "crm_acl_stats_ingress_rif_crm_stats_acl_table_used",
)
crm_acl_stats_ingress_rif_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_rif_crm_stats_acl_group_available",
    "crm_acl_stats_ingress_rif_crm_stats_acl_group_available",
)
crm_acl_stats_ingress_rif_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_rif_crm_stats_acl_table_available",
    "crm_acl_stats_ingress_rif_crm_stats_acl_table_available",
)

crm_acl_stats_ingress_switch_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_switch_crm_stats_acl_group_used",
    "crm_acl_stats_ingress_switch_crm_stats_acl_group_used",
)
crm_acl_stats_ingress_switch_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_switch_crm_stats_acl_table_used",
    "crm_acl_stats_ingress_switch_crm_stats_acl_table_used",
)
crm_acl_stats_ingress_switch_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_switch_crm_stats_acl_group_available",
    "crm_acl_stats_ingress_switch_crm_stats_acl_group_available",
)
crm_acl_stats_ingress_switch_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_switch_crm_stats_acl_table_available",
    "crm_acl_stats_ingress_switch_crm_stats_acl_table_available",
)

crm_acl_stats_ingress_vlan_crm_stats_acl_group_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_vlan_crm_stats_acl_group_used",
    "crm_acl_stats_ingress_vlan_crm_stats_acl_group_used",
)
crm_acl_stats_ingress_vlan_crm_stats_acl_table_used = GaugeMetricFamily(
    "crm_acl_stats_ingress_vlan_crm_stats_acl_table_used",
    "crm_acl_stats_ingress_vlan_crm_stats_acl_table_used",
)
crm_acl_stats_ingress_vlan_crm_stats_acl_group_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_vlan_crm_stats_acl_group_available",
    "crm_acl_stats_ingress_vlan_crm_stats_acl_group_available",
)
crm_acl_stats_ingress_vlan_crm_stats_acl_table_available = GaugeMetricFamily(
    "crm_acl_stats_ingress_vlan_crm_stats_acl_table_available",
    "crm_acl_stats_ingress_vlan_crm_stats_acl_table_available",
)

crm_stats_dnat_entry_used = GaugeMetricFamily(
    "crm_stats_dnat_entry_used", "crm_stats_dnat_entry_used"
)
crm_stats_fdb_entry_used = GaugeMetricFamily(
    "crm_stats_fdb_entry_used", "crm_stats_fdb_entry_used"
)
crm_stats_ipmc_entry_used = GaugeMetricFamily(
    "crm_stats_ipmc_entry_used", "crm_stats_ipmc_entry_used"
)
crm_stats_ipv4_neighbor_used = GaugeMetricFamily(
    "crm_stats_ipv4_neighbor_used", "crm_stats_ipv4_neighbor_used"
)
crm_stats_ipv4_nexthop_used = GaugeMetricFamily(
    "crm_stats_ipv4_nexthop_used", "crm_stats_ipv4_nexthop_used"
)
crm_stats_ipv4_route_used = GaugeMetricFamily(
    "crm_stats_ipv4_route_used", "crm_stats_ipv4_route_used"
)
crm_stats_ipv6_neighbor_used = GaugeMetricFamily(
    "crm_stats_ipv6_neighbor_used", "crm_stats_ipv6_neighbor_used"
)
crm_stats_ipv6_nexthop_used = GaugeMetricFamily(
    "crm_stats_ipv6_nexthop_used", "crm_stats_ipv6_nexthop_used"
)
crm_stats_ipv6_route_used = GaugeMetricFamily(
    "crm_stats_ipv6_route_used", "crm_stats_ipv6_route_used"
)
crm_stats_nexthop_group_member_used = GaugeMetricFamily(
    "crm_stats_nexthop_group_member_used", "crm_stats_nexthop_group_member_used"
)
crm_stats_nexthop_group_used = GaugeMetricFamily(
    "crm_stats_nexthop_group_used", "crm_stats_nexthop_group_used"
)
crm_stats_snat_entry_used = GaugeMetricFamily(
    "crm_stats_snat_entry_used", "crm_stats_snat_entry_used"
)
crm_stats_dnat_entry_available = GaugeMetricFamily(
    "crm_stats_dnat_entry_available", "crm_stats_dnat_entry_available"
)
crm_stats_fdb_entry_available = GaugeMetricFamily(
    "crm_stats_fdb_entry_available", "crm_stats_fdb_entry_available"
)
crm_stats_ipmc_entry_available = GaugeMetricFamily(
    "crm_stats_ipmc_entry_available", "crm_stats_ipmc_entry_available"
)
crm_stats_ipv4_neighbor_available = GaugeMetricFamily(
    "crm_stats_ipv4_neighbor_available", "crm_stats_ipv4_neighbor_available"
)
crm_stats_ipv4_nexthop_available = GaugeMetricFamily(
    "crm_stats_ipv4_nexthop_available", "crm_stats_ipv4_nexthop_available"
)
crm_stats_ipv4_route_available = GaugeMetricFamily(
    "crm_stats_ipv4_route_available", "crm_stats_ipv4_route_available"
)
crm_stats_ipv6_neighbor_available = GaugeMetricFamily(
    "crm_stats_ipv6_neighbor_available", "crm_stats_ipv6_neighbor_available"
)
crm_stats_ipv6_nexthop_available = GaugeMetricFamily(
    "crm_stats_ipv6_nexthop_available", "crm_stats_ipv6_nexthop_available"
)
crm_stats_ipv6_route_available = GaugeMetricFamily(
    "crm_stats_ipv6_route_available", "crm_stats_ipv6_route_available"
)
crm_stats_nexthop_group_available = GaugeMetricFamily(
    "crm_stats_nexthop_group_available", "crm_stats_nexthop_group_available"
)
crm_stats_nexthop_group_member_available = GaugeMetricFamily(
    "crm_stats_nexthop_group_member_available",
    "crm_stats_nexthop_group_member_available",
)
crm_stats_snat_entry_available = GaugeMetricFamily(
    "crm_stats_snat_entry_available", "crm_stats_snat_entry_available"
)


def export_crm():
    try:
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:LAG"
        )
        crm_acl_stats_egress_lag_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_egress_lag_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_egress_lag_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_egress_lag_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:PORT"
        )
        crm_acl_stats_egress_port_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_egress_port_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_egress_port_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_egress_port_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:RIF"
        )
        crm_acl_stats_egress_rif_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_egress_rif_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_egress_rif_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_egress_rif_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:SWITCH"
        )
        crm_acl_stats_egress_switch_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_egress_switch_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_egress_switch_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_egress_switch_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:VLAN"
        )
        crm_acl_stats_egress_vlan_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_egress_vlan_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_egress_vlan_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_egress_vlan_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )

        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:LAG"
        )
        crm_acl_stats_ingress_lag_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_ingress_lag_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_ingress_lag_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_ingress_lag_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:PORT"
        )
        crm_acl_stats_ingress_port_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_ingress_port_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_ingress_port_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_ingress_port_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:RIF"
        )
        crm_acl_stats_ingress_rif_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_ingress_rif_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_ingress_rif_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_ingress_rif_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:SWITCH"
        )
        crm_acl_stats_ingress_switch_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_ingress_switch_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_ingress_switch_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_ingress_switch_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )
        out_put = getAllFromDB(
            sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:VLAN"
        )
        crm_acl_stats_ingress_vlan_crm_stats_acl_group_used.add_metric(
            [], out_put.get("crm_stats_acl_group_used",0)
        )
        crm_acl_stats_ingress_vlan_crm_stats_acl_table_used.add_metric(
            [], out_put.get("crm_stats_acl_table_used",0)
        )
        crm_acl_stats_ingress_vlan_crm_stats_acl_group_available.add_metric(
            [], out_put.get("crm_stats_acl_group_available",0)
        )
        crm_acl_stats_ingress_vlan_crm_stats_acl_table_available.add_metric(
            [], out_put.get("crm_stats_acl_table_available",0)
        )

        out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:STATS")
        crm_stats_dnat_entry_used.add_metric(
            [], out_put.get("crm_stats_dnat_entry_used",0)
        )
        crm_stats_fdb_entry_used.add_metric(
            [], out_put.get("crm_stats_fdb_entry_used",0)
        )
        crm_stats_ipmc_entry_used.add_metric(
            [], out_put.get("crm_stats_ipmc_entry_used",0)
        )
        crm_stats_ipv4_neighbor_used.add_metric(
            [], out_put.get("crm_stats_ipv4_neighbor_used",0)
        )
        crm_stats_ipv4_nexthop_used.add_metric(
            [], out_put.get("crm_stats_ipv4_nexthop_used",0)
        )
        crm_stats_ipv4_route_used.add_metric(
            [], out_put.get("crm_stats_ipv4_route_used",0)
        )
        crm_stats_ipv6_neighbor_used.add_metric(
            [], out_put.get("crm_stats_ipv6_neighbor_used",0)
        )
        crm_stats_ipv6_nexthop_used.add_metric(
            [], out_put.get("crm_stats_ipv6_nexthop_used",0)
        )
        crm_stats_ipv6_route_used.add_metric(
            [], out_put.get("crm_stats_ipv6_route_used",0)
        )
        crm_stats_nexthop_group_member_used.add_metric(
            [], out_put.get("crm_stats_nexthop_group_member_used",0)
        )
        crm_stats_nexthop_group_used.add_metric(
            [], out_put.get("crm_stats_nexthop_group_used",0)
        )
        crm_stats_snat_entry_used.add_metric(
            [], out_put.get("crm_stats_snat_entry_used",0)
        )
        crm_stats_dnat_entry_available.add_metric(
            [], out_put.get("crm_stats_dnat_entry_available",0)
        )
        crm_stats_fdb_entry_available.add_metric(
            [], out_put.get("crm_stats_fdb_entry_available",0)
        )
        crm_stats_ipmc_entry_available.add_metric(
            [], out_put.get("crm_stats_ipmc_entry_available",0)
        )
        crm_stats_ipv4_neighbor_available.add_metric(
            [], out_put.get("crm_stats_ipv4_neighbor_available",0)
        )
        crm_stats_ipv4_nexthop_available.add_metric(
            [], out_put.get("crm_stats_ipv4_nexthop_available",0)
        )
        crm_stats_ipv4_route_available.add_metric(
            [], out_put.get("crm_stats_ipv4_route_available",0)
        )
        crm_stats_ipv6_neighbor_available.add_metric(
            [], out_put.get("crm_stats_ipv6_neighbor_available",0)
        )
        crm_stats_ipv6_nexthop_available.add_metric(
            [], out_put.get("crm_stats_ipv6_nexthop_available",0)
        )
        crm_stats_ipv6_route_available.add_metric(
            [], out_put.get("crm_stats_ipv6_route_available",0)
        )
        crm_stats_nexthop_group_available.add_metric(
            [], out_put.get("crm_stats_nexthop_group_available",0)
        )
        crm_stats_nexthop_group_member_available.add_metric(
            [], out_put.get("crm_stats_nexthop_group_member_available",0)
        )
        crm_stats_snat_entry_available.add_metric(
            [], out_put.get("crm_stats_snat_entry_available",0)
        )

    except Exception as e:
        _logger.info(e)
