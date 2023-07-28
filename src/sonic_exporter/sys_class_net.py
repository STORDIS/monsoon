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
from pathlib import Path

from .converters import boolify


class SystemClassNetworkInfo:
    class NetworkInfoAttribute(enum.Enum):
        CARRIER = "carrier"
        FLAGS = "flags"

    def get_attribute_info(
        self, interface: str, attribute: NetworkInfoAttribute
    ) -> str:
        with open(Path("/sys/class/net") / interface / attribute.value, "r") as file:
            data = file.read()
        return str(data).strip()

    def operational(self, interface: str) -> bool:
        data = self.get_attribute_info(
            interface, SystemClassNetworkInfo.NetworkInfoAttribute.CARRIER
        )
        return boolify(data)

    def admin_enabled(self, interface: str) -> bool:
        data = self.get_attribute_info(
            interface, SystemClassNetworkInfo.NetworkInfoAttribute.FLAGS
        )
        if int(data, 16) & 0x1:
            return True
        return False
