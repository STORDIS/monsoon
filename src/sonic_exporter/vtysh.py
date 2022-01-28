import enum
from subprocess import run, PIPE
import json

from typing import Optional


class VtySH:
    class AddressFamily(enum.Enum):
        IPV4 = "ipv4Unicast"
        IPV6 = "ipv6Unicast"
        L2VPN_EVPN = "l2VpnEvpn"

    @staticmethod
    def addressfamily(family: AddressFamily):
        match family:
            case VtySH.AddressFamily.IPV4:
                return "ipv4"
            case VtySH.AddressFamily.IPV6:
                return "ipv6"
            case VtySH.AddressFamily.L2VPN_EVPN:
                return "evpn"

    @staticmethod
    def run_command(command: str):
        return json.loads(
            run(
                ["vtysh", "-c", f"{command.rstrip()} json"], check=True, stdout=PIPE
            ).stdout.decode("utf-8")
        )

    def show_bgp_vrf_all_l2vpn_evpn_summary(self, vrf: Optional[str] = None) -> dict:
        data = VtySH.run_command("show bgp vrf all ipv4 unicast summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_ipv4_unicast_summary(self, vrf: Optional[str] = None) -> dict:
        data = VtySH.run_command("show bgp vrf all ipv6 unicast summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_ipv6_unicast_summary(self, vrf: Optional[str] = None) -> dict:
        data = VtySH.run_command("show bgp vrf all l2vpn evpn summary")
        if vrf is not None:
            return data[vrf]
        return data

    def show_bgp_vrf_all_summary(self, vrf: Optional[str] = None) -> dict:
        data = VtySH.run_command("show bgp vrf all summary")
        if vrf is not None:
            return data[vrf]
        return data
