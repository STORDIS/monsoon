import json
from importlib.resources import read_text

from sonic_exporter.enums import SwitchModel
from sonic_exporter.sys_class_hwmon import LinuxHWMon, Sensor
from sonic_exporter.test import ressources


class MockLinuxHWMon(LinuxHWMon):

    model: SwitchModel = SwitchModel.AS5853

    @property
    def sensors(self) -> dict[str, Sensor]:
        return {
            key: Sensor.from_dict(value)
            for key, value in json.loads(
                read_text(ressources, f"{self.model.value}.hwmon.json").items()
            )
        }
