import logging
from prometheus_client.core import GaugeMetricFamily
from .constants import (
    SAG,
    SAG_GLOBAL,
    SAG_PATTERN,
    VLAN_INTERFACE,
    VXLAN_TUNNEL_MAP_PATTERN,
)
from .converters import boolify
from .db_util import getAllFromDB, getFromDB, getKeysFromDB, sonic_db
from .converters import decode
from .utilities import developer_mode
from .enums import InternetProtocol

_logger = logging.getLogger(__name__)

sag_labels = [
    "interface",
    "vrf",
    "gateway_ip",
    "ip_family",
    "vni",
]
metric_sag_operational_status = GaugeMetricFamily(
    "sonic_sag_operational_status",
    "Reports the operational status of the Static Anycast Gateway (0(DOWN)/1(UP))",
    labels=sag_labels,
)
metric_sag_admin_status = GaugeMetricFamily(
    "sonic_sag_admin_status",
    "Reports the admin status of the Static Anycast Gateway (0(DOWN)/1(UP))",
    labels=sag_labels,
)
metric_sag_info = GaugeMetricFamily(
    "sonic_sag_info",
    "Static Anycast Gateway General Information",
    labels=["ip_family", "mac_address"],
)

if developer_mode:
    from sonic_exporter.test.mock_sys_class_net import (
        MockSystemClassNetworkInfo,
    )

    sys_class_net = MockSystemClassNetworkInfo()
else:
    from sonic_exporter.sys_class_net import SystemClassNetworkInfo

    sys_class_net = SystemClassNetworkInfo()


def export_static_anycast_gateway_info():
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
    keys = getKeysFromDB(sonic_db.CONFIG_DB, SAG_PATTERN)
    if not list(keys):
        # break if no SAG is configured
        return
    global_data = getAllFromDB(sonic_db.CONFIG_DB, SAG_GLOBAL)
    vxlan_tunnel_map = getKeysFromDB(sonic_db.CONFIG_DB, VXLAN_TUNNEL_MAP_PATTERN)

    for internet_protocol in InternetProtocol:
        if global_data and boolify(global_data[internet_protocol.value].lower()):
            exportable[internet_protocol] = True
            metric_sag_info.add_metric(
                [internet_protocol.value.lower(), decode(global_data["gwmac"])], 1
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
                vrf = decode(
                    getFromDB(
                        sonic_db.CONFIG_DB,
                        f"{VLAN_INTERFACE}{interface}",
                        "vrf_name",
                    )
                )
                gateway_ip = decode(getFromDB(sonic_db.CONFIG_DB, key, "gwip@"))
                vni_key = next(
                    vxlan_tunnel_key
                    for vxlan_tunnel_key in vxlan_tunnel_map
                    if decode(vxlan_tunnel_key).endswith(interface)
                )
                vni = decode(getFromDB(sonic_db.CONFIG_DB, vni_key, "vni"))
                metric_sag_admin_status.add_metric(
                    [interface, vrf, gateway_ip, ip_family.value.lower(), str(vni)],
                    sys_class_net.admin_enabled(interface),
                )
                metric_sag_operational_status.add_metric(
                    [interface, vrf, gateway_ip, ip_family.value.lower(), str(vni)],
                    sys_class_net.operational(interface),
                )
            except (KeyError, StopIteration, OSError):
                _logger.debug(
                    f"export_static_anycast_gateway_info :: No Static Anycast Gateway for interface={interface}"
                )
                pass
