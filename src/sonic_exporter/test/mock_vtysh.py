import json
from importlib.resources import read_text

from sonic_exporter.enums import SwitchModel
from sonic_exporter.test import ressources
from sonic_exporter.vtysh import VtySH


class MockVtySH(VtySH):

    model: SwitchModel = SwitchModel.AS5853

    def run_command(self, command: str):
        path = command.replace(" ", "_")
        return json.loads(read_text(ressources, f"{self.model.value}.frr.{path}.json"))
