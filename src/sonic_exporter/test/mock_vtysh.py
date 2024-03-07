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
from importlib.resources import read_text

from sonic_exporter.enums import SwitchModel
from sonic_exporter.test.resources import frr
from sonic_exporter.vtysh import VtySH


class MockVtySH(VtySH):
    model: SwitchModel = SwitchModel.AS7726

    def run_command(self, command: str):
        path = command.replace(" ", "_")
        return json.loads(read_text(frr, f"{self.model.value}.frr.{path}.json"))
