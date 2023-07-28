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

import logging
from prometheus_client.core import GaugeMetricFamily

from .constants import VXLAN_TUNNEL_TABLE, VXLAN_TUNNEL_TABLE_PATTERN
from .converters import boolify
from .db_util import getFromDB, getKeysFromDB, sonic_db
from .converters import decode
from .utilities import dns_lookup

_logger = logging.getLogger(__name__)

metric_vxlan_operational_status = GaugeMetricFamily(
    "sonic_vxlan_operational_status",
    "Reports the status of the VXLAN Tunnel to Endpoints (0(DOWN)/1(UP))",
    labels=["neighbor"],
)


def export_vxlan_tunnel_info():
    keys = getKeysFromDB(sonic_db.STATE_DB, VXLAN_TUNNEL_TABLE_PATTERN)
    if not keys:
        return
    for key in keys:
        try:
            neighbor = ""
            _, neighbor = tuple(key.replace(VXLAN_TUNNEL_TABLE, "").split("_"))
            is_operational = boolify(
                decode(getFromDB(sonic_db.STATE_DB, key, "operstatus"))
            )
            metric_vxlan_operational_status.add_metric(
                [dns_lookup(neighbor)], is_operational
            )
            _logger.debug(
                f"export_vxlan_tunnel :: neighbor={neighbor}, is_operational={is_operational}"
            )
        except ValueError as e:
            pass
