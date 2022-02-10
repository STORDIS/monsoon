import enum


class OSILayer(enum.Enum):
    L2 = "l2"
    L3 = "l3"


class InternetProtocol(enum.Enum):
    v4 = "IPv4"
    v6 = "IPv6"


class AddressFamily(enum.Enum):
    IPV4 = "ipv4Unicast"
    IPV6 = "ipv6Unicast"
    L2VPN_EVPN = "l2VpnEvpn"


class SwitchModel(enum.Enum):
    AS7326 = "x86_64-accton_as7326_56x-r0"
    AS7726 = "x86_64-accton_as7726_32x-r0"
    AS5853 = "x86_64-accton_as5835_54t-r0"
