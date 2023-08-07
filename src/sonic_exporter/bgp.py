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

from .enums import AddressFamily
from .utilities import dns_lookup, thread_pool, get_logger
from .vtysh import vtysh

_logger = get_logger().getLogger(__name__)


class BgpCollector():

    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [
                thread_pool.submit(self.export_bgp_info)
            ],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(
            f"Time taken in metrics collection {datetime.now() - date_time}"
        )
        yield self.metric_bgp_uptime_seconds
        yield self.metric_bgp_status
        yield self.metric_bgp_prefixes_received
        yield self.metric_bgp_prefixes_transmitted
        yield self.metric_bgp_messages_received
        yield self.metric_bgp_messages_transmitted

    def __init_metrics(self):
        bgp_labels = [
            "vrf",
            "as",
            "peer_name",
            "peer_host",
            "ip_family",
            "message_type",
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
        bgp_vrf_all = vtysh.show_bgp_vrf_all_summary()
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
                            peerdata.get("hostname", dns_lookup(peername)),
                            peerdata.get("idType", ""),
                            vtysh.addressfamily(family),
                            str(peerdata.get("remoteAs")),
                        ]
                        self.metric_bgp_uptime_seconds.add_metric(
                            [*bgp_lbl],
                            floatify(peerdata.get(
                                "peerUptimeMsec", 1000) / 1000),
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
