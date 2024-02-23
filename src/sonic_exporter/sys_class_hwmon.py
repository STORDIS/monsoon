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
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from dacite import Config, from_dict

"""
    ref: https://www.kernel.org/doc/Documentation/hwmon/sysfs-interface
"""


class SIUnit(enum.Enum):
    VOLTAGE = "voltage"
    ROUNDSPERMINUTE = "rpm"
    RATIO = "ratio"
    CELSIUS = "celsius"
    HERTZ = "hertz"
    AMPERES = "amperes"
    WATTS = "watts"
    JOULES = "joules"
    SECONDS = "seconds"
    FLAG = "status"


@dataclass
class BaseSerializer:
    @staticmethod
    def to_serializable(value):
        match value:
            case enum.Enum():
                return value.value
            case str():
                return str(value)
            case int():
                return int(value)
            case _:
                return value

    @staticmethod
    def to_complex_serializable(data):
        match data:
            case list() | set():
                return [BaseSerializer.to_complex_serializable(item) for item in data]
            case dict():
                return {
                    BaseSerializer.to_serializable(
                        key
                    ): BaseSerializer.to_complex_serializable(val)
                    for key, val in data.items()
                }
            case _:
                return BaseSerializer.to_serializable(data)

    @staticmethod
    def dict_factory(data):
        return {
            field: BaseSerializer.to_complex_serializable(value)
            for field, value in data
        }

    @classmethod
    def from_dict(cls, data: dict):
        return from_dict(
            cls,
            data,
            config=Config(
                cast=[
                    enum.Enum,
                    set,
                ],
                check_types=True,
                strict=True,
                strict_unions_match=True,
            ),
        )

    def as_dict(self) -> dict:
        return asdict(self, dict_factory=BaseSerializer.dict_factory)

    @property
    def object_name(self) -> str:
        return self.__class__.__name__


@dataclass
class SensorData(BaseSerializer):
    name: str
    value: float
    unit: SIUnit


@dataclass
class Sensor(BaseSerializer):
    address: Optional[str]
    modalias: Optional[str]
    values: List[SensorData] = field(default_factory=list)


class SystemClassHWMon:
    """
    ref: https://www.kernel.org/doc/Documentation/hwmon/sysfs-interface
    Naming and data format standards for sysfs files
    ------------------------------------------------

    The libsensors library offers an interface to the raw sensors data
    through the sysfs interface. Since lm-sensors 3.0.0, libsensors is
    completely chip-independent. It assumes that all the kernel drivers
    implement the standard sysfs interface described in this document.
    This makes adding or updating support for any given chip very easy, as
    libsensors, and applications using it, do not need to be modified.
    This is a major improvement compared to lm-sensors 2.

    Note that motherboards vary widely in the connections to sensor chips.
    There is no standard that ensures, for example, that the second
    temperature sensor is connected to the CPU, or that the second fan is on
    the CPU. Also, some values reported by the chips need some computation
    before they make full sense. For example, most chips can only measure
    voltages between 0 and +4V. Other voltages are scaled back into that
    range using external resistors. Since the values of these resistors
    can change from motherboard to motherboard, the conversions cannot be
    hard coded into the driver and have to be done in user space.

    For this reason, even if we aim at a chip-independent libsensors, it will
    still require a configuration file (e.g. /etc/sensors.conf) for proper
    values conversion, labeling of inputs and hiding of unused inputs.

    An alternative method that some programs use is to access the sysfs
    files directly. This document briefly describes the standards that the
    drivers follow, so that an application program can scan for entries and
    access this data in a simple and consistent way. That said, such programs
    will have to implement conversion, labeling and hiding of inputs. For
    this reason, it is still not recommended to bypass the library.

    Each chip gets its own directory in the sysfs /sys/devices tree.  To
    find all sensor chips, it is easier to follow the device symlinks from
    /sys/class/hwmon/hwmon*.

    Up to lm-sensors 3.0.0, libsensors looks for hardware monitoring attributes
    in the "physical" device directory. Since lm-sensors 3.0.1, attributes found
    in the hwmon "class" device directory are also supported. Complex drivers
    (e.g. drivers for multifunction chips) may want to use this possibility to
    avoid namespace pollution. The only drawback will be that older versions of
    libsensors won't support the driver in question.

    All sysfs values are fixed point numbers.

    There is only one value per file, unlike the older /proc specification.
    The common scheme for files naming is: <type><number>_<item>. Usual
    types for sensor chips are "in" (voltage), "temp" (temperature) and
    "fan" (fan). Usual items are "input" (measured value), "max" (high
    threshold, "min" (low threshold). Numbering usually starts from 1,
    except for voltages which start from 0 (because most data sheets use
    this). A number is always used for elements that can be present more
    than once, even if there is a single element of the given type on the
    specific chip. Other files do not refer to a specific element, so
    they have a simple name, and no number.

    Alarms are direct indications read from the chips. The drivers do NOT
    make comparisons of readings to thresholds. This allows violations
    between readings to be caught and alarmed. The exact definition of an
    alarm (for example, whether a threshold must be met or must be exceeded
    to cause an alarm) is chip-dependent.

    When setting values of hwmon sysfs attributes, the string representation of
    the desired value must be written, note that strings which are not a number
    are interpreted as 0! For more on how written strings are interpreted see the
    "sysfs attribute writes interpretation" section at the end of this file.

    -------------------------------------------------------------------------

    [0-*]	denotes any positive number starting from 0
    [1-*]	denotes any positive number starting from 1
    RO	read only value
    WO	write only value
    RW	read/write value

    Read/write values may be read-only for some chips, depending on the
    hardware implementation.

    All entries (except name) are optional, and should only be created in a
    given driver if the chip has the feature.
    """

    sys_path = Path("/sys/class/hwmon")
    _data: Dict[str, Sensor] = {}

    class SensorType(enum.Enum):
        TEMPERATURE = "temp"
        INLET = "in"
        FAN = "fan"
        PWM = "pwm"
        CURRENT = "curr"
        POWER = "power"
        ENERGY = "energy"
        HUMIDITY = "humidity"
        VOLTAGE = "voltage"

    class SensorFlags(enum.Enum):
        FAULT = "fault"
        PRESENT = "present"
        DIRECTION = "direction"
        BEEP = "beep"
        ENABLE = "enable"

    class GlobalAttributes(enum.Enum):
        NAME = "name"
        LABEL = "label"
        UPDATE_INTERVAL = "update_interval"
        DEVICE = "device"
        SUBSYSTEM = "subsystem"
        MODALIAS = "modalias"

    class UnImportantAttributes(enum.Enum):
        DPM_FORCE_PERFORMANCE_LEVEL = "dpm_force_performance_level"
        DPM_STATE = "dpm_state"
        STATE = "state"

    sensor_regex = re.compile(
        r"^({})(\d+)_((?!{}).*?)$".format(
            "|".join([sensor_type.value for sensor_type in SensorType]),
            "|".join(
                (
                    [sensor_type.value for sensor_type in GlobalAttributes]
                    + [none.value for none in UnImportantAttributes]
                )
            ),
        )
    )
    # logging.debug(sensor_regex.pattern)

    @staticmethod
    def to_si_unit_value(
        metric_name: str, data: str, sensor_type: SensorType
    ) -> SensorData:
        try:
            match sensor_type:
                case (
                    SystemClassHWMon.SensorType.INLET
                    | SystemClassHWMon.SensorType.VOLTAGE
                ):
                    si_unit = SIUnit.VOLTAGE
                    value = int(data) / 1000
                case SystemClassHWMon.SensorType.TEMPERATURE:
                    si_unit = SIUnit.CELSIUS
                    value = int(data) / 1000
                case SystemClassHWMon.SensorType.FAN:
                    si_unit = SIUnit.ROUNDSPERMINUTE
                    value = int(data)
                case SystemClassHWMon.SensorType.PWM:
                    si_unit = SIUnit.RATIO
                    value = int(data) / 255
                case SystemClassHWMon.SensorType.CURRENT:
                    si_unit = SIUnit.AMPERES
                    value = int(data) / 1000
                case SystemClassHWMon.SensorType.POWER:
                    si_unit = SIUnit.WATTS
                    value = int(data) / 1000000
                case SystemClassHWMon.SensorType.HUMIDITY:
                    si_unit = SIUnit.RATIO
                    value = int(data) / 1000
                case SystemClassHWMon.SensorType.ENERGY:
                    si_unit = SIUnit.JOULES
                    value = int(data) / 1000000
        except ValueError as e:
            # logging.debug(metric_name, data)
            raise e
        if metric_name.endswith("percentage"):
            si_unit = SIUnit.RATIO
            value = int(data) / 100
        elif any(
            [
                metric_name.endswith(value)
                for value in [flag.value for flag in SystemClassHWMon.SensorFlags]
            ]
        ):
            si_unit = SIUnit.FLAG
            value = int(data)
        return SensorData(name=metric_name, unit=si_unit, value=value)

    @staticmethod
    def get_sensor_data(file_path: Path) -> Optional[SensorData]:
        if match := SystemClassHWMon.sensor_regex.match(file_path.name):
            sensor_type = SystemClassHWMon.SensorType(match.group(1))
            try:
                with open(file_path, "r") as file:
                    return SystemClassHWMon.to_si_unit_value(
                        file_path.name, file.read().strip(), sensor_type
                    )
            except OSError:
                pass
                # logging.debug(e)
        # else:
        # logging.debug(file_path.name)
        return None

    @property
    def sensors(self) -> Dict[str, Sensor]:
        for file_path in self.sys_path.iterdir():
            if file_path.is_dir():
                name = ""
                address = None
                modalias = None
                name_path = file_path / self.GlobalAttributes.NAME.value
                address_path = file_path / self.GlobalAttributes.DEVICE.value
                device_path = None
                if name_path.exists():
                    with open(name_path, "r") as file:
                        name = file.read().strip()
                if address_path.exists():
                    address_path = address_path.readlink()
                    address = address_path.name
                    device_path = file_path.joinpath(address_path)
                    name = f"{name}:{address}"
                    modalias_path = device_path / self.GlobalAttributes.MODALIAS.value
                    if modalias_path.exists():
                        with open(modalias_path, "r") as file:
                            modalias = file.read().strip()
                self._data[name] = Sensor(address, modalias)
                for child_file_path in file_path.iterdir():
                    if child_file_path.is_file():
                        if data := SystemClassHWMon.get_sensor_data(child_file_path):
                            self._data[name].values.append(data)
                if device_path is None:
                    continue
                for child_file_path in device_path.iterdir():
                    if child_file_path.is_file():
                        if data := SystemClassHWMon.get_sensor_data(child_file_path):
                            self._data[name].values.append(data)

        return self._data


if __name__ == "__main__":
    sensors = SystemClassHWMon().sensors
    print(
        json.dumps(
            {key: sensor.as_dict() for key, sensor in sensors.items()},
            indent=2,
        )
    )
