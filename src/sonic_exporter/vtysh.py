import json
from subprocess import PIPE, run
from typing import Optional

from sonic_exporter.enums import AddressFamily


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
            return json.loads(
                run(
                    ["vtysh", "-c", f"{command.rstrip()} json"], check=True, stdout=PIPE
                ).stdout.decode("utf-8")
            )
        except json.JSONDecodeError:
            return {}

    def show_bgp_vrf_all_l2vpn_evpn_summary(self, vrf: Optional[str] = None) -> dict:
        data = self.run_command("show bgp vrf all ipv4 unicast summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_ipv4_unicast_summary(self, vrf: Optional[str] = None) -> dict:
        data = self.run_command("show bgp vrf all ipv6 unicast summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_ipv6_unicast_summary(self, vrf: Optional[str] = None) -> dict:
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
