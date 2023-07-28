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
from .enums import OSILayer
from .converters import boolify, decode, floatify
from .vtysh import vtysh
from .utilities import developer_mode

_logger = logging.getLogger(__name__)

evpn_vni_labels = ["vni", "interface", "svi", "osi_layer", "vrf"]

metric_evpn_status = GaugeMetricFamily(
    "sonic_evpn_status",
    "The Status of the EVPN Endpoints",
    labels=evpn_vni_labels,
)
metric_evpn_remote_vteps = GaugeMetricFamily(
    "sonic_evpn_remote_vteps",
    "The number of remote VTEPs associated with that VNI",
    labels=evpn_vni_labels,
)

metric_evpn_l2_vnis = GaugeMetricFamily(
    "sonic_evpn_l2_vnis",
    "The number of l2 vnis associated with an l3 VNI",
    labels=evpn_vni_labels,
)
metric_evpn_mac_addresses = GaugeMetricFamily(
    "sonic_evpn_mac_addresses",
    "The number of Mac Addresses learned VNI",
    labels=evpn_vni_labels,
)
metric_evpn_arps = GaugeMetricFamily(
    "sonic_evpn_arps",
    "The number of ARPs cached for the VNI",
    labels=evpn_vni_labels,
)

if developer_mode:
    from sonic_exporter.test.mock_sys_class_net import (
        MockSystemClassNetworkInfo,
    )

    sys_class_net = MockSystemClassNetworkInfo()
else:
    from sonic_exporter.sys_class_net import SystemClassNetworkInfo

    sys_class_net = SystemClassNetworkInfo()


def export_evpn_vni_info():
    evpn_vni_detail = vtysh.show_evpn_vni_detail()
    for evpn_vni in evpn_vni_detail:
        vni = decode(str(evpn_vni["vni"]))
        interface = ""
        svi = ""
        layer = decode(OSILayer(evpn_vni["type"].lower()))
        vrf = decode(evpn_vni["vrf"])
        state = False
        match layer:
            case OSILayer.L3:
                svi = decode(evpn_vni["sviIntf"])
                interface = decode(evpn_vni["vxlanIntf"])
                state = decode(evpn_vni["state"].lower())
                metric_evpn_l2_vnis.add_metric(
                    [vni, interface, svi, layer.value, vrf],
                    floatify(len(evpn_vni["l2Vnis"])),
                )
            case OSILayer.L2:
                interface = decode(evpn_vni["vxlanInterface"])
                state = sys_class_net.operational(interface)
                metric_evpn_remote_vteps.add_metric(
                    [vni, interface, svi, layer.value, vrf],
                    floatify(len(evpn_vni.get("numRemoteVteps", []))),
                )
                metric_evpn_arps.add_metric(
                    [vni, interface, svi, layer.value, vrf], evpn_vni["numArpNd"]
                )
                metric_evpn_mac_addresses.add_metric(
                    [vni, interface, svi, layer.value, vrf],
                    floatify(evpn_vni["numMacs"]),
                )
        metric_evpn_status.add_metric(
            [vni, interface, svi, layer.value, vrf], boolify(state)
        )
