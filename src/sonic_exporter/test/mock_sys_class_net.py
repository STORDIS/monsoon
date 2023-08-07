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

from sonic_exporter.sys_class_net import SystemClassNetworkInfo


class MockSystemClassNetworkInfo(SystemClassNetworkInfo):
    def get_attribute_info(
        self, interface: str, attribute: SystemClassNetworkInfo.NetworkInfoAttribute
    ) -> str:
        match attribute:
            case SystemClassNetworkInfo.NetworkInfoAttribute.FLAGS:
                return "0x1003"
            case SystemClassNetworkInfo.NetworkInfoAttribute.CARRIER:
                return "1"
            case _:
                raise NotImplementedError(
                    f"The NetworkInfoAttribute: [{attribute}] is not implemented in {self.__class__.__name__}"
                )
