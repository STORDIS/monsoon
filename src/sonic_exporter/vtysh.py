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
from subprocess import CalledProcessError, run
from typing import Optional, Tuple, Union

from .enums import AddressFamily, SubsequentAddressFamily
from .utilities import developer_mode


class VtySH:
    @staticmethod
    def get_protocol_family(afi: AddressFamily) -> str:
        assert afi in [AddressFamily.IPV4, AddressFamily.IPV6]
        match afi:
            case AddressFamily.IPV4:
                return "ip"
            case AddressFamily.IPV6:
                return AddressFamily.IPV6.value

    @staticmethod
    def get_safi(prefix: str, afi_safi: str):
        safi = afi_safi.removeprefix(prefix)
        return SubsequentAddressFamily(safi)

    @staticmethod
    def get_afi_safi(
        afi_safi: str,
    ) -> Tuple[Optional[AddressFamily], Optional[SubsequentAddressFamily]]:
        afi_safi = afi_safi.lower()
        for afi in AddressFamily:
            if afi_safi.startswith(afi.value):
                return afi, vtysh.get_safi(afi.value, afi_safi)
        return None, None

    def run_command(self, command: str):
        try:
            process = run(
                ["vtysh", "-c", f"{command.rstrip()} json"],
                check=True,
                capture_output=True,
            )
            try:
                return json.loads(process.stdout.decode("utf-8"))
            except json.JSONDecodeError:
                return {}
        except CalledProcessError:
            return {}

    def show_bgp_vrf_afi_safi_neighbors_flap_statistics(
        self,
        vrf: str,
        neighbor: str,
        afi: Optional[AddressFamily],
        safi: Optional[SubsequentAddressFamily] = None,
    ) -> dict:
        assert afi in [AddressFamily.IPV4, AddressFamily.IPV6]
        if safi is None:
            return self.run_command(
                f"show bgp vrf {vrf} {afi.value} neighbors {neighbor} flap-statistics"
            )
        return self.run_command(
            f"show bgp vrf {vrf} {afi.value} {safi.value} neighbors {neighbor} flap-statistics"
        )

    def show_bgp_vrf_afi_safi_neighbors_prefix_counts(
        self,
        vrf: str,
        neighbor: str,
        afi: Optional[AddressFamily],
        safi: Optional[SubsequentAddressFamily] = None,
    ) -> dict:
        assert afi in [AddressFamily.IPV4, AddressFamily.IPV6]
        if safi is None:
            return self.run_command(
                f"show bgp vrf {vrf} {afi.value} neighbors {neighbor} prefix-counts"
            )
        return self.run_command(
            f"show bgp vrf {vrf} {afi.value} {safi.value} neighbors {neighbor} prefix-counts"
        )

    def show_bgp_vrf_afi_safi_neighbors_received_routes(
        self,
        vrf: str,
        neighbor: str,
        afi: Optional[AddressFamily],
        safi: Optional[SubsequentAddressFamily] = None,
    ) -> dict:
        assert afi in [AddressFamily.IPV4, AddressFamily.IPV6]
        if safi is None:
            return self.run_command(
                f"show bgp vrf {vrf} {afi.value} neighbors {neighbor} received-routes"
            )
        return self.run_command(
            f"show bgp vrf {vrf} {afi.value} {safi.value} neighbors {neighbor} received-routes"
        )

    def show_bgp_vrf_afi_safi_neighbors_advertised_routes(
        self,
        vrf: str,
        neighbor: str,
        afi: AddressFamily,
        safi: Optional[SubsequentAddressFamily] = None,
    ) -> dict:
        assert afi in [AddressFamily.IPV4, AddressFamily.IPV6]
        if safi is None:
            return self.run_command(
                f"show bgp vrf {vrf} {afi.value} neighbors {neighbor} advertised-routes"
            )
        return self.run_command(
            f"show bgp vrf {vrf} {afi.value} {safi.value} neighbors {neighbor} advertised-routes"
        )

    def show_bgp_vrf_afi_safi_summary(
        self,
        vrf: str,
        afi: Optional[AddressFamily] = None,
        safi: Optional[SubsequentAddressFamily] = None,
    ) -> dict:
        if afi is not None:
            if safi is not None:
                return self.run_command(f"show bgp vrf {vrf} {afi} {safi} summary")
            return self.run_command(f"show bgp vrf {vrf} {afi} summary")
        return self.run_command(f"show bgp vrf {vrf} summary")

    def show_route_vrf_summary(
        self,
        afi: AddressFamily,
        vrf: str,
    ) -> dict:
        afi_string = VtySH.get_protocol_family(afi)
        return self.run_command(f"show {afi_string} route vrf {vrf} summary")

    def show_bgp_vrf_all_summary(self) -> dict:
        return self.show_bgp_vrf_afi_safi_summary("all")

    def show_ipv6_route_vrf_all_summary(self) -> dict:
        return self.show_route_vrf_summary(AddressFamily.IPV6, "all")

    def show_ip_route_vrf_all_summary(self) -> dict:
        return self.show_route_vrf_summary(AddressFamily.IPV4, "all")

    def show_evpn_vni_detail(self) -> dict:
        data = self.run_command("show evpn vni detail")
        return data


vtysh: Union[VtySH, "MockVtySH"]

if developer_mode:
    from sonic_exporter.test.mock_vtysh import MockVtySH

    vtysh = MockVtySH()
else:
    vtysh = VtySH()
