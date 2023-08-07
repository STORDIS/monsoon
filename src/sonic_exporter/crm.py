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

from concurrent.futures import ALL_COMPLETED, wait
from datetime import datetime
import traceback
from prometheus_client.core import GaugeMetricFamily

from .utilities import get_logger, thread_pool
from .db_util import getAllFromDB
from .db_util import sonic_db

_logger = get_logger().getLogger(__name__)


class CrmCollector:
    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [thread_pool.submit(self.export_crm)],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(f"Time taken in metrics collection {datetime.now() - date_time}")
        yield self.crm_acl_stats_egress_lag_crm_stats_acl_group_used
        yield self.crm_acl_stats_egress_lag_crm_stats_acl_table_used
        yield self.crm_acl_stats_egress_port_crm_stats_acl_group_used
        yield self.crm_acl_stats_egress_port_crm_stats_acl_table_used
        yield self.crm_acl_stats_egress_rif_crm_stats_acl_group_used
        yield self.crm_acl_stats_egress_rif_crm_stats_acl_table_used
        yield self.crm_acl_stats_egress_switch_crm_stats_acl_group_used
        yield self.crm_acl_stats_egress_switch_crm_stats_acl_table_used
        yield self.crm_acl_stats_egress_vlan_crm_stats_acl_group_used
        yield self.crm_acl_stats_egress_vlan_crm_stats_acl_table_used
        yield self.crm_acl_stats_ingress_lag_crm_stats_acl_group_used
        yield self.crm_acl_stats_ingress_lag_crm_stats_acl_table_used
        yield self.crm_acl_stats_ingress_port_crm_stats_acl_group_used
        yield self.crm_acl_stats_ingress_port_crm_stats_acl_table_used
        yield self.crm_acl_stats_ingress_rif_crm_stats_acl_group_used
        yield self.crm_acl_stats_ingress_rif_crm_stats_acl_table_used
        yield self.crm_acl_stats_ingress_switch_crm_stats_acl_group_used
        yield self.crm_acl_stats_ingress_switch_crm_stats_acl_table_used
        yield self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_used
        yield self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_used
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

    def __init_metrics(self):
        lbl = ["available"]
        self.crm_acl_stats_egress_lag_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_lag_crm_stats_acl_group_used",
            "crm_acl_stats_egress_lag_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_egress_lag_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_lag_crm_stats_acl_table_used",
            "crm_acl_stats_egress_lag_crm_stats_acl_table_used",
            labels=lbl,
        )
        self.crm_acl_stats_egress_port_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_port_crm_stats_acl_group_used",
            "crm_acl_stats_egress_port_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_egress_port_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_port_crm_stats_acl_table_used",
            "crm_acl_stats_egress_port_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_egress_rif_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_rif_crm_stats_acl_group_used",
            "crm_acl_stats_egress_rif_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_egress_rif_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_rif_crm_stats_acl_table_used",
            "crm_acl_stats_egress_rif_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_egress_switch_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_switch_crm_stats_acl_group_used",
            "crm_acl_stats_egress_switch_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_egress_switch_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_switch_crm_stats_acl_table_used",
            "crm_acl_stats_egress_switch_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_egress_vlan_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_egress_vlan_crm_stats_acl_group_used",
            "crm_acl_stats_egress_vlan_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_egress_vlan_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_egress_vlan_crm_stats_acl_table_used",
            "crm_acl_stats_egress_vlan_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_ingress_lag_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_lag_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_lag_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_ingress_lag_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_lag_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_lag_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_ingress_port_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_port_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_port_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_ingress_port_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_port_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_port_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_ingress_rif_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_rif_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_rif_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_ingress_rif_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_rif_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_rif_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_ingress_switch_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_switch_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_switch_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_ingress_switch_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_switch_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_switch_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_vlan_crm_stats_acl_group_used",
            "crm_acl_stats_ingress_vlan_crm_stats_acl_group_used",
            labels=lbl,
        )
        self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_used = GaugeMetricFamily(
            "crm_acl_stats_ingress_vlan_crm_stats_acl_table_used",
            "crm_acl_stats_ingress_vlan_crm_stats_acl_table_used",
            labels=lbl,
        )

        self.crm_stats_dnat_entry_used = GaugeMetricFamily(
            "crm_stats_dnat_entry_used", "crm_stats_dnat_entry_used", labels=lbl
        )
        self.crm_stats_fdb_entry_used = GaugeMetricFamily(
            "crm_stats_fdb_entry_used", "crm_stats_fdb_entry_used", labels=lbl
        )
        self.crm_stats_ipmc_entry_used = GaugeMetricFamily(
            "crm_stats_ipmc_entry_used", "crm_stats_ipmc_entry_used", labels=lbl
        )
        self.crm_stats_ipv4_neighbor_used = GaugeMetricFamily(
            "crm_stats_ipv4_neighbor_used", "crm_stats_ipv4_neighbor_used", labels=lbl
        )
        self.crm_stats_ipv4_nexthop_used = GaugeMetricFamily(
            "crm_stats_ipv4_nexthop_used", "crm_stats_ipv4_nexthop_used", labels=lbl
        )
        self.crm_stats_ipv4_route_used = GaugeMetricFamily(
            "crm_stats_ipv4_route_used", "crm_stats_ipv4_route_used", labels=lbl
        )
        self.crm_stats_ipv6_neighbor_used = GaugeMetricFamily(
            "crm_stats_ipv6_neighbor_used", "crm_stats_ipv6_neighbor_used", labels=lbl
        )
        self.crm_stats_ipv6_nexthop_used = GaugeMetricFamily(
            "crm_stats_ipv6_nexthop_used", "crm_stats_ipv6_nexthop_used", labels=lbl
        )
        self.crm_stats_ipv6_route_used = GaugeMetricFamily(
            "crm_stats_ipv6_route_used", "crm_stats_ipv6_route_used", labels=lbl
        )
        self.crm_stats_nexthop_group_member_used = GaugeMetricFamily(
            "crm_stats_nexthop_group_member_used",
            "crm_stats_nexthop_group_member_used",
            labels=lbl,
        )
        self.crm_stats_nexthop_group_used = GaugeMetricFamily(
            "crm_stats_nexthop_group_used", "crm_stats_nexthop_group_used", labels=lbl
        )
        self.crm_stats_snat_entry_used = GaugeMetricFamily(
            "crm_stats_snat_entry_used", "crm_stats_snat_entry_used", labels=lbl
        )

    def export_crm(self):
        try:
            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:LAG")
            if out_put:
                self.crm_acl_stats_egress_lag_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_egress_lag_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:PORT")
            if out_put:
                self.crm_acl_stats_egress_port_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_egress_port_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:RIF")
            if out_put:
                self.crm_acl_stats_egress_rif_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_egress_rif_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:SWITCH")
            if out_put:
                self.crm_acl_stats_egress_switch_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_egress_switch_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:EGRESS:VLAN")
            if out_put:
                self.crm_acl_stats_egress_vlan_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_egress_vlan_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:LAG")
            if out_put:
                self.crm_acl_stats_ingress_lag_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_ingress_lag_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:PORT")
            if out_put:
                self.crm_acl_stats_ingress_port_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_ingress_port_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:RIF")
            if out_put:
                self.crm_acl_stats_ingress_rif_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_ingress_rif_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:SWITCH")
            if out_put:
                self.crm_acl_stats_ingress_switch_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_ingress_switch_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:ACL_STATS:INGRESS:VLAN")
            if out_put:
                self.crm_acl_stats_ingress_vlan_crm_stats_acl_group_used.add_metric(
                    [str(out_put.get("crm_stats_acl_group_available", 0))],
                    out_put.get("crm_stats_acl_group_used", 0),
                )
                self.crm_acl_stats_ingress_vlan_crm_stats_acl_table_used.add_metric(
                    [str(out_put.get("crm_stats_acl_table_available", 0))],
                    out_put.get("crm_stats_acl_table_used", 0),
                )

            out_put = getAllFromDB(sonic_db.COUNTERS_DB, "CRM:STATS")
            if out_put:
                self.crm_stats_dnat_entry_used.add_metric(
                    [str(out_put.get("crm_stats_dnat_entry_available", 0))],
                    out_put.get("crm_stats_dnat_entry_used", 0),
                )
                self.crm_stats_fdb_entry_used.add_metric(
                    [str(out_put.get("crm_stats_fdb_entry_available", 0))],
                    out_put.get("crm_stats_fdb_entry_used", 0),
                )
                self.crm_stats_ipmc_entry_used.add_metric(
                    [str(out_put.get("crm_stats_ipmc_entry_available", 0))],
                    out_put.get("crm_stats_ipmc_entry_used", 0),
                )
                self.crm_stats_ipv4_neighbor_used.add_metric(
                    [str(out_put.get("crm_stats_ipv4_neighbor_available", 0))],
                    out_put.get("crm_stats_ipv4_neighbor_used", 0),
                )
                self.crm_stats_ipv4_nexthop_used.add_metric(
                    [str(out_put.get("crm_stats_ipv4_nexthop_available", 0))],
                    out_put.get("crm_stats_ipv4_nexthop_used", 0),
                )
                self.crm_stats_ipv4_route_used.add_metric(
                    [str(out_put.get("crm_stats_ipv4_route_available", 0))],
                    out_put.get("crm_stats_ipv4_route_used", 0),
                )
                self.crm_stats_ipv6_neighbor_used.add_metric(
                    [str(out_put.get("crm_stats_ipv6_neighbor_available", 0))],
                    out_put.get("crm_stats_ipv6_neighbor_used", 0),
                )
                self.crm_stats_ipv6_nexthop_used.add_metric(
                    [str(out_put.get("crm_stats_ipv6_nexthop_available", 0))],
                    out_put.get("crm_stats_ipv6_nexthop_used", 0),
                )
                self.crm_stats_ipv6_route_used.add_metric(
                    [str(out_put.get("crm_stats_ipv6_route_available", 0))],
                    out_put.get("crm_stats_ipv6_route_used", 0),
                )
                self.crm_stats_nexthop_group_member_used.add_metric(
                    [str(out_put.get("crm_stats_nexthop_group_member_available", 0))],
                    out_put.get("crm_stats_nexthop_group_member_used", 0),
                )
                self.crm_stats_nexthop_group_used.add_metric(
                    [str(out_put.get("crm_stats_nexthop_group_available", 0))],
                    out_put.get("crm_stats_nexthop_group_used", 0),
                )
                self.crm_stats_snat_entry_used.add_metric(
                    [str(out_put.get("crm_stats_snat_entry_available", 0))],
                    out_put.get("crm_stats_snat_entry_used", 0),
                )

        except:
            _logger.error(traceback.print_exc())
