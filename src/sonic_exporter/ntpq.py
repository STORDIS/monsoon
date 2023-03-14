import jc
import logging
from subprocess import PIPE, CalledProcessError, run
from typing import Optional


class NTPQ:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def run_command(self, command: list, vrf: Optional[str] = None):
        ## TODO: Put local VRF commands into their own module
        command = ["ntpq"] + command
        if vrf:
            command = [
                "cgexec",
                "-g",
                f"l3mdev:{vrf.strip()}",
            ] + command
        try:
            out_put = run(command, check=True, stdout=PIPE, stderr=PIPE).stdout.decode(
                "utf-8"
            )
            self.logger.debug(f"run command [{' '.join(command)}]")
            self.logger.debug(f"got output \n {out_put}")
            return out_put
        except CalledProcessError as e:
            self.logger.debug(
                f"{e.cmd} error_code: {e.returncode} error_msg: {e.stderr} output: {e.stdout}"
            )
            raise e

    def get_peers(
        self,
        vrf: Optional[str] = None,
    ):
        data = jc.parse("ntpq", self.run_command(["-p", "-n"], vrf=vrf))
        self.logger.debug(f"parsed data :: {data}")
        return data

    def get_rv(self, vrf: Optional[str] = None):
        rv = {}
        output = self.run_command(["-c", "rv"], vrf=vrf)
        for element in output.replace("\n", "").split(","):
            try:
                key, value = element.strip().split("=", maxsplit=1)
                rv[key] = value.replace('"', "")
            except ValueError:
                self.logger.debug(f"[{element}] is not '=' separated")
                continue
        return rv


if __name__ == "__main__":
    import json
    from .test.mock_ntpq import MockNTPQ

    print(json.dumps(MockNTPQ().get_peers(), indent=2))
    print(json.dumps(MockNTPQ().get_rv(), indent=2))
    print(json.dumps(NTPQ().get_peers(), indent=2))
    print(json.dumps(NTPQ().get_rv(), indent=2))
