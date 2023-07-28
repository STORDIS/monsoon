from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from .converters import boolify, floatify

from .enums import AddressFamily
from .utilities import dns_lookup
from .vtysh import vtysh

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
metric_bgp_uptime_seconds = CounterMetricFamily(
    "sonic_bgp_uptime_seconds_total",
    "Uptime of the session with the other BGP Peer",
    labels=bgp_labels,
)
metric_bgp_status = GaugeMetricFamily(
    "sonic_bgp_status",
    "The Session Status to the other BGP Peer",
    labels=bgp_labels,
)
metric_bgp_prefixes_received = CounterMetricFamily(
    "sonic_bgp_prefixes_received_total",
    "The Prefixes Received from the other peer.",
    labels=bgp_labels,
)
metric_bgp_prefixes_transmitted = CounterMetricFamily(
    "sonic_bgp_prefixes_transmitted_total",
    "The Prefixes Transmitted to the other peer.",
    labels=bgp_labels,
)
metric_bgp_messages_received = CounterMetricFamily(
    "sonic_bgp_messages_received_total",
    "The messages Received from the other peer.",
    labels=bgp_labels,
)
metric_bgp_messages_transmitted = CounterMetricFamily(
    "sonic_bgp_messages_transmitted_total",
    "The messages Transmitted to the other peer.",
    labels=bgp_labels,
)


def export_bgp_info():
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
                    metric_bgp_uptime_seconds.add_metric(
                        [*bgp_lbl],
                        floatify(peerdata.get("peerUptimeMsec", 1000) / 1000),
                    )
                    metric_bgp_status.add_metric(
                        [*bgp_lbl], boolify(peerdata.get("state", ""))
                    )
                    metric_bgp_prefixes_received.add_metric(
                        [*bgp_lbl], floatify(peerdata.get("pfxRcd", 0))
                    )
                    metric_bgp_prefixes_transmitted.add_metric(
                        [*bgp_lbl], floatify(peerdata.get("pfxSnt", 0))
                    )
                    metric_bgp_messages_received.add_metric(
                        [*bgp_lbl], floatify(peerdata.get("msgRcvd", 0))
                    )
                    metric_bgp_messages_transmitted.add_metric(
                        [*bgp_lbl], floatify(peerdata.get("msgSent", 0))
                    )
            except KeyError:
                pass
