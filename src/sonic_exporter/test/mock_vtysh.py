import json
import enum
from importlib.resources import read_text
from typing import Optional
from sonic_exporter.test import ressources
from sonic_exporter.test.mock_db import SwitchModel


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
    def run_command(command: str, model: SwitchModel = SwitchModel.AS7726):
        path = command.replace(" ", "_")
        return json.loads(read_text(ressources, f"{model.value}.frr.{path}.json"))

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
