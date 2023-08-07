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

import prometheus_client as prom


class CustomCounter(prom.Counter):
    def set(self, value):
        """Set gauge to the given value."""
        self._raise_if_not_observable()
        self._value.set(float(value))

    def _child_samples(self):
        return (("_total", {}, self._value.get(), None, self._value.get_exemplar()),)
