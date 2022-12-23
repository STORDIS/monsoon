import jc
from subprocess import PIPE, CalledProcessError, run
from typing import Optional

from sonic_exporter.utilities import ConfigDBVersion


class NTPQ:
    def run_command(
        self, command: list, db_version: ConfigDBVersion, vrf: Optional[str] = None
    ):
        ## TODO: Put local VRF commands into their own module
        assert isinstance(db_version, ConfigDBVersion)
        new_command = []
        if self.vrf:
            if db_version < ConfigDBVersion("version_4_0_0"):
                new_command = [
                    "cgexec",
                    "-g",
                    f"l3mdev:{vrf.strip()}",
                    "ntpq",
                ] + command
            else:
                new_command = ["ip", "vrf", "exec", f"{vrf.strip()}", "ntpq"] + command
        else:
            new_command = ["ntpq"] + command
        try:
            out_put = run(new_command, check=True, stdout=PIPE).stdout.decode("utf-8")
            return jc.parse("ntpq", out_put)
        except CalledProcessError as e:
            raise e

    def get_associations(
        self,
        db_version: ConfigDBVersion = ConfigDBVersion("version_3_4_1"),
        vrf: Optional[str] = None,
    ):
        return self.run_command(["-p"], db_version=db_version, vrf=vrf)
