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
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from .converters import boolify, floatify

from .utilities import dns_lookup, thread_pool, get_logger
from .vtysh import vtysh

_logger = get_logger().getLogger(__name__)


class BgpCollector:
    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [thread_pool.submit(self.export_bgp_info)],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(f"Time taken in metrics collection {datetime.now() - date_time}")
        yield self.metric_bgp_uptime_seconds
        yield self.metric_bgp_status
        yield self.metric_bgp_prefixes_received
        yield self.metric_bgp_prefixes_transmitted
        yield self.metric_bgp_messages_received
        yield self.metric_bgp_messages_transmitted
        yield self.metric_bgp_routes_received
        yield self.metric_bgp_routes_advertised

    def __init_metrics(self):
        bgp_labels = [
            "vrf",
            "as",
            "peer",
            "neighbor",
            "peer_protocol",
            "afi",
            "safi",
            "remote_as",
        ]
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
        self.metric_bgp_prefixes_received = GaugeMetricFamily(
            "sonic_bgp_prefixes_received",
            "The Prefixes Received from the other peer.",
            labels=bgp_labels,
        )
        self.metric_bgp_prefixes_transmitted = GaugeMetricFamily(
            "sonic_bgp_prefixes_transmitted",
            "The Prefixes Advertised to the other peer.",
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
        self.metric_bgp_routes_received = GaugeMetricFamily(
            "sonic_bgp_routes_received",
            "The amount of routes received from neighbor",
            labels=bgp_labels,
        )
        self.metric_bgp_routes_advertised = GaugeMetricFamily(
            "sonic_bgp_routes_advertised",
            "The amount of routes advertised to neighbor",
            labels=bgp_labels,
        )
        self.metric_bgp_routes_rib = GaugeMetricFamily(
            "sonic_bgp_routes_rib",
            "The amount of routes learnt into RIB",
            labels=bgp_labels,
        )

    def export_bgp_info(self):
        # vtysh -c "show bgp vrf all ipv4 unicast summary json"
        # vtysh -c "show bgp vrf all ipv6 unicast summary json"
        # vtysh -c "show bgp vrf all l2vpn evpn summary json"
        # vtysh -c "show bgp vrf all summary json"
        # vtysh -c "show bgp vrf <vrf> ipv4 unicast neighbors <peername> json"
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
        bgp_vrf_all = vtysh.show_bgp_vrf_all_summary()
        for vrf in bgp_vrf_all:
            for family in bgp_vrf_all[vrf].keys():
                family_data = None
                afi, safi = vtysh.get_afi_safi(family)
                try:
                    family_data = bgp_vrf_all[vrf][family]
                    as_id = family_data.get("as")
                    for peername, peerdata in family_data["peers"].items():
                        remote = peerdata.get("hostname", dns_lookup(peername))
                        _logger.debug(
                            f"Exporting Metrics for: {peername}->{remote} afi: {afi} safi: {safi} frr_family: {family}"
                        )
                        # ["vrf", "peername", "neighbor", "peer_protocol", "protocol_family_advertised", "remote_as"]
                        bgp_lbl = [
                            vrf,
                            str(as_id),
                            peername,
                            remote,
                            peerdata.get("idType", ""),
                            afi.value,
                            safi.value,
                            str(peerdata.get("remoteAs")),
                        ]
                        prefix_counts_data = (
                            vtysh.show_bgp_vrf_afi_safi_neighbors_prefix_counts(
                                vrf, neighbor=peername, afi=afi, safi=safi
                            )
                        )
                        if "warning" in prefix_counts_data.keys():
                            _logger.info(
                                f"Skipped vrf because of not existant neighbor config: {vrf} afi: {afi} safi: {safi} neighbor: {remote}"
                            )
                            continue
                        advertised_routes_data = (
                            vtysh.show_bgp_vrf_afi_safi_neighbors_advertised_routes(
                                vrf, neighbor=peername, afi=afi, safi=safi
                            )
                        )
                        received_routes_data = (
                            vtysh.show_bgp_vrf_afi_safi_neighbors_received_routes(
                                vrf, neighbor=peername, afi=afi, safi=safi
                            )
                        )

                        advertised_routes = len(
                            advertised_routes_data.get("advertisedRoutes", {})
                        )
                        received_routes = len(
                            received_routes_data.get("receivedRoutes", {})
                        )
                        self.metric_bgp_routes_advertised.add_metric(
                            [*bgp_lbl], floatify(advertised_routes)
                        )
                        self.metric_bgp_routes_received.add_metric(
                            [*bgp_lbl], floatify(received_routes)
                        )
                        self.metric_bgp_routes_rib.add_metric(
                            [*bgp_lbl], floatify(prefix_counts_data.get("All RIB", 0))
                        )
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
