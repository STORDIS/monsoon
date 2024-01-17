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

import enum


class OSILayer(enum.Enum):
    L2 = "l2"
    L3 = "l3"


class InternetProtocol(enum.Enum):
    v4 = "IPv4"
    v6 = "IPv6"


# AFI
class AddressFamily(enum.Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    L2VPN = "l2vpn"


# SAFI
class SubsequentAddressFamily(enum.Enum):
    UNICAST = "unicast"
    MULTICAST = "multicast"
    EVPN = "evpn"


class SwitchModel(enum.Enum):
    AS7326 = "x86_64-accton_as7326_56x-r0"
    AS7726 = "x86_64-accton_as7726_32x-r0"
    AS5853 = "x86_64-accton_as5835_54t-r0"
    AS9716 = "x86_64-accton_as9716_32d-r0"


class AlarmType(enum.Enum):
    HIGH_ALARM = "high_alarm"
    HIGH_WARNING = "high_warning"
    LOW_ALARM = "low_alarm"
    LOW_WARNING = "low_warning"


class AirFlow(enum.Enum):
    FRONT_TO_BACK = "F"
    BACK_TO_FRONT = "B"
