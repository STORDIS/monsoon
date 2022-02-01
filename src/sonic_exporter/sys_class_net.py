import enum
from pathlib import Path

from sonic_exporter.converters import boolify


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
