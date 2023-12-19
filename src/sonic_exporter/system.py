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

from concurrent.futures import ALL_COMPLETED, wait
from typing import Union
from datetime import datetime
import re
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from .constants import (
    CHASSIS_INFO,
    CHASSIS_INFO_PATTERN,
    EEPROM_INFO,
    EEPROM_INFO_PATTERN,
    PROCESS_STATS,
    PROCESS_STATS_IGNORE,
    PROCESS_STATS_PATTERN,
    TEMP_SENSORS,
    TEMPERATURE_INFO_PATTERN,
)
from .db_util import (
    getAllFromDB,
    getFromDB,
    getKeysFromDB,
    is_sonic_sys_ready,
    sonic_db,
)

from .enums import AirFlow, AlarmType, SwitchModel
from .converters import decode, floatify, get_uptime
from .utilities import developer_mode, get_logger, thread_pool

_logger = get_logger().getLogger(__name__)

sys_class_hwmon: Union["MockSystemClassHWMon", "SystemClassHWMon"]

if developer_mode:
    from sonic_exporter.test.mock_sys_class_hwmon import MockSystemClassHWMon

    sys_class_hwmon = MockSystemClassHWMon()
else:
    from sonic_exporter.sys_class_hwmon import SystemClassHWMon

    sys_class_hwmon = SystemClassHWMon()

chassis_slot_regex = re.compile(r"^.*?(\d+)$")


def get_syseeprom():
    return {
        decode(key)
        .replace(EEPROM_INFO, "")
        .replace(" ", "_")
        .lower(): getAllFromDB(sonic_db.STATE_DB, key)
        for key in getKeysFromDB(sonic_db.STATE_DB, EEPROM_INFO_PATTERN)
    }


def get_chassis_info():
    return {
        decode(key).replace(CHASSIS_INFO, ""): getAllFromDB(sonic_db.STATE_DB, key)
        for key in getKeysFromDB(sonic_db.STATE_DB, CHASSIS_INFO_PATTERN)
    }


def _find_in_syseeprom(key: str):
    return list(
        set(
            syseeprom.get("Value", "")
            for syseeprom in get_syseeprom().values()
            if str(syseeprom.get("Name", "")).replace(" ", "_").lower() == key
        )
    )[0].strip()


class SystemCollector:
    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [
                thread_pool.submit(self.export_temp_info),
                thread_pool.submit(self.export_system_info),
                thread_pool.submit(self.export_sys_status),
            ],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(f"Time taken in metrics collection {datetime.now() - date_time}")
        yield self.metric_sys_status
        yield self.metric_device_sensor_celsius
        yield self.metric_device_threshold_sensor_celsius
        yield self.metric_device_uptime
        yield self.metric_device_info
        yield self.system_memory_ratio
        yield self.system_cpu_ratio

    def __init_metrics(self):
        self.metric_sys_status = GaugeMetricFamily(
            "sonic_system_status",
            "SONiC System Status",
        )

        # Temp Info
        self.metric_device_sensor_celsius = GaugeMetricFamily(
            "sonic_device_sensor_celsius",
            "Show the temperature of the Sensors in the switch",
            labels=["name"],
        )
        self.metric_device_threshold_sensor_celsius = GaugeMetricFamily(
            "sonic_device_sensor_threshold_celsius",
            f"Thresholds for the temperature sensors {', '.join(alarm_type.value for alarm_type in AlarmType)}",
            labels=["name", "alarm_type"],
        )

        # System Info
        self.metric_device_uptime = CounterMetricFamily(
            "sonic_device_uptime_seconds_total", "The uptime of the device in seconds"
        )
        self.metric_device_info = GaugeMetricFamily(
            "sonic_device_info",
            "part name, serial number, MAC address and software vesion of the System",
            labels=[
                "chassis",
                "platform_name",
                "part_number",
                "serial_number",
                "mac_address",
                "software_version",
                "onie_version",
                "hardware_revision",
                "product_name",
            ],
        )
        self.system_memory_ratio = GaugeMetricFamily(
            "sonic_device_memory_ratio",
            "Memory Usage of the device in percentage [0-1]",
        )
        self.system_cpu_ratio = GaugeMetricFamily(
            "sonic_device_cpu_ratio", "CPU Usage of the device in percentage [0-1]"
        )

    def export_hwmon_temp_info(self, switch_model, air_flow):
        for name, sensor in sys_class_hwmon.sensors.items():
            try:
                last_two_bytes = sensor.address[-2:]
                name = TEMP_SENSORS[switch_model][air_flow][last_two_bytes]
            except (ValueError, KeyError, TypeError) as e:
                _logger.debug(
                    f"export_hwmon_temp_info :: air_flow={air_flow}, switch_mode={switch_model} address={last_two_bytes}, e={e}"
                )
                continue

            for value in sensor.values:
                _, subvalue = value.name.split("_", maxsplit=1)
                _logger.debug(
                    f"export_hwmon_temp_info :: name={name}, -> value={value}"
                )
                match subvalue:
                    case "max":
                        self.metric_device_threshold_sensor_celsius.add_metric(
                            [name, AlarmType.HIGH_ALARM.value], value.value
                        )
                    case "max_hyst":
                        self.metric_device_threshold_sensor_celsius.add_metric(
                            [name, AlarmType.HIGH_WARNING.value], value.value
                        )
                    case "input":
                        self.metric_device_sensor_celsius.add_metric(
                            [name], value.value
                        )

    def export_temp_info(self):
        platform_name: str = list(
            set(
                decode(chassis.get("platform_name", ""))
                for chassis in get_chassis_info().values()
            )
        )[0].strip()
        if not platform_name:
            platform_name = _find_in_syseeprom("platform_name")
        product_name = list(
            set(
                decode(chassis.get("product_name", ""))
                for chassis in get_chassis_info().values()
            )
        )[0].strip()
        if not product_name:
            product_name = _find_in_syseeprom("product_name")

        keys = getKeysFromDB(sonic_db.STATE_DB, TEMPERATURE_INFO_PATTERN)
        need_additional_temp_info = False
        unknown_switch_model = False
        air_flow = None
        switch_model = None
        try:
            air_flow = AirFlow(product_name[-1])
            switch_model = SwitchModel(platform_name.lower())
        except ValueError as e:
            _logger.debug(f"export_temp_info :: exception={e}")
            unknown_switch_model = True
            pass

        for key in keys or []:
            try:
                name = decode(getFromDB(sonic_db.STATE_DB, key, "name"))
                if name.lower().startswith("temp"):
                    need_additional_temp_info = True
                last_two_bytes: str = name[-2:]
                if not unknown_switch_model:
                    name = TEMP_SENSORS[switch_model][air_flow].get(
                        last_two_bytes, name
                    )

                temp = floatify(
                    decode(getFromDB(sonic_db.STATE_DB, key, "temperature"))
                )
                high_threshold = floatify(
                    decode(getFromDB(sonic_db.STATE_DB, key, "high_threshold"))
                )
                self.metric_device_sensor_celsius.add_metric([name], temp)
                self.metric_device_threshold_sensor_celsius.add_metric(
                    [name, AlarmType.HIGH_ALARM.value], high_threshold
                )
                _logger.debug(
                    f"export_temp_info :: name={name}, temp={temp}, high_threshold={high_threshold}"
                )
            except ValueError:
                pass

        if (not keys or need_additional_temp_info) and not unknown_switch_model:
            self.export_hwmon_temp_info(switch_model, air_flow)

    def export_system_info(self):
        self.metric_device_uptime.add_metric([], get_uptime().total_seconds())
        for chassis_raw, data in get_chassis_info().items():
            chs = chassis_raw
            if match := chassis_slot_regex.fullmatch(chassis_raw):
                chs = match.group(1)
            part_number = decode(data.get("part_num", ""))
            serial_number = decode(data.get("serial_num", ""))
            mac_address = decode(data.get("base_mac_addr", ""))
            onie_version = decode(data.get("onie_version", ""))
            software_version = decode(
                getFromDB(sonic_db.STATE_DB, "IMAGE_GLOBAL|config", "current")
            )
            platform_name = decode(data.get("platform_name", ""))
            hardware_revision = decode(data.get("hardware_revision", ""))
            product_name = decode(data.get("product_name", ""))
            self.metric_device_info.add_metric(
                [
                    chs,
                    platform_name,
                    part_number,
                    serial_number,
                    mac_address,
                    software_version,
                    onie_version,
                    hardware_revision,
                    product_name,
                ],
                1,
            )
            _logger.debug(
                "export_sys_info :: part_num={}, serial_num={}, mac_addr={}, software_version={}".format(
                    part_number, serial_number, mac_address, software_version
                )
            )
        keys = getKeysFromDB(sonic_db.STATE_DB, PROCESS_STATS_PATTERN)
        cpu_memory_usages = [
            (
                floatify(decode(getFromDB(sonic_db.STATE_DB, key, "%CPU"))),
                floatify(decode(getFromDB(sonic_db.STATE_DB, key, "%MEM"))),
            )
            for key in keys
            if not key.replace(PROCESS_STATS, "").lower() in PROCESS_STATS_IGNORE
        ]
        cpu_usage = sum(cpu_usage for cpu_usage, _ in cpu_memory_usages)
        memory_usage = sum(memory_usage for _, memory_usage in cpu_memory_usages)
        self.system_cpu_ratio.add_metric([], cpu_usage / 100)
        self.system_memory_ratio.add_metric([], memory_usage / 100)
        _logger.debug(
            f"export_sys_info :: cpu_usage={cpu_usage}, memory_usage={memory_usage}"
        )

    def export_sys_status(self):
        sts, sts_core = is_sonic_sys_ready()
        self.metric_sys_status.add_metric([], floatify(sts & sts_core))
