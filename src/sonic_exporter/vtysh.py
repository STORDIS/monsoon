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

import json
from subprocess import PIPE, CalledProcessError, run
from typing import Optional

from .enums import AddressFamily
from .utilities import developer_mode


class VtySH:
    @staticmethod
    def addressfamily(family: AddressFamily):
        match family:
            case AddressFamily.IPV4:
                return "ipv4"
            case AddressFamily.IPV6:
                return "ipv6"
            case AddressFamily.L2VPN_EVPN:
                return "evpn"

    def run_command(self, command: str):
        try:
            out_put = run(
                ["vtysh", "-c", f"{command.rstrip()} json"], check=True, stdout=PIPE
            ).stdout.decode("utf-8")
            try:
                return json.loads(out_put)
            except json.JSONDecodeError:
                return {}
        except CalledProcessError:
            return {}

    def show_bgp_vrf_all_ipv4_unicast_summary(self, vrf: Optional[str] = None) -> dict:
        data = self.run_command("show bgp vrf all ipv4 unicast summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_ipv6_unicast_summary(self, vrf: Optional[str] = None) -> dict:
        data = self.run_command("show bgp vrf all ipv6 unicast summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_l2vpn_evpn_summary(self, vrf: Optional[str] = None) -> dict:
        data = self.run_command("show bgp vrf all l2vpn evpn summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_summary(self, vrf: Optional[str] = None) -> dict:
        data = self.run_command("show bgp vrf all summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_evpn_vni_detail(self) -> dict:
        data = self.run_command("show evpn vni detail")
        return data


if developer_mode:
    from sonic_exporter.test.mock_vtysh import MockVtySH

    vtysh = MockVtySH()
else:
    vtysh = VtySH()
