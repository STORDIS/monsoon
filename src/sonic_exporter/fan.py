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
import re
from prometheus_client.core import GaugeMetricFamily
from .constants import FAN_INFO_PATTERN, PSU_INFO
from .db_util import getFromDB, getKeysFromDB, sonic_db
from .converters import boolify, decode, floatify

_logger = logging.getLogger(__name__)

metric_device_fan_rpm = GaugeMetricFamily(
    "sonic_device_fan_rpm",
    "The Rounds per minute of the fan",
    labels=["name", "slot"],
)
metric_device_fan_operational_status = GaugeMetricFamily(
    "sonic_device_fan_operational_status",
    "Shows if a fan is Operational (0(DOWN)/1(UP))",
    labels=["name", "slot"],
)
metric_device_fan_available_status = GaugeMetricFamily(
    "sonic_device_fan_available_status",
    "Shows if a fan is plugged in (0(DOWN)/1(UP))",
    labels=["name", "slot"],
)
fan_slot_regex = re.compile(r"^((?:PSU|Fantray).*?\d+).*?(?!FAN|_).*?(\d+)$")


def export_fan_info():
    keys = getKeysFromDB(sonic_db.STATE_DB, FAN_INFO_PATTERN)
    if not keys:
        return
    for key in keys:
        try:
            fullname = decode(getFromDB(sonic_db.STATE_DB, key, "name"))
            rpm = floatify(getFromDB(sonic_db.STATE_DB, key, "speed"))
            is_operational = decode(getFromDB(sonic_db.STATE_DB, key, "status"))
            is_available = boolify(
                decode(getFromDB(sonic_db.STATE_DB, key, "presence"))
            )
            name = fullname
            slot = "0"
            if match := fan_slot_regex.fullmatch(fullname):
                name = match.group(1).rstrip()
                slot = match.group(2).strip()
                # This handles the special case of the AS7326 which bounds health of the PSU Fan to the Health of the Power Supply
                if is_operational is None and fullname.lower().startswith("psu"):
                    is_operational = boolify(
                        decode(
                            getFromDB(
                                sonic_db.STATE_DB,
                                f"{PSU_INFO}{name}",
                                "status",
                            )
                        )
                    )
            metric_device_fan_rpm.add_metric([name, slot], rpm)
            metric_device_fan_operational_status.add_metric(
                [name, slot], boolify(is_operational)
            )
            metric_device_fan_available_status.add_metric([name, slot], is_available)
            _logger.debug(
                f"export_fan_info :: fullname={fullname} oper={boolify(is_operational)}, presence={is_available}, rpm={rpm}"
            )
        except ValueError:
            pass
