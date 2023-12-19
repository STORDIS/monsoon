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
from datetime import datetime
import jc
from subprocess import PIPE, CalledProcessError, run
from typing import Optional

from .utilities import get_logger, thread_pool
from .constants import NTP_SERVER_PATTERN, TRUE_VALUES

from .converters import floatify
from .db_util import getAllFromDB, getFromDB, getKeysFromDB, sonic_db
from prometheus_client.core import GaugeMetricFamily


_logger = get_logger().getLogger(__name__)


class NTPQ:
    def run_command(self, command: list, vrf: Optional[str] = None):
        # TODO: Put local VRF commands into their own module
        command = ["ntpq"] + command
        if vrf in TRUE_VALUES:
            command = [
                "cgexec",
                "-g",
                f"l3mdev:mgmt",
            ] + command
        try:
            out_put = run(command, check=True, stdout=PIPE, stderr=PIPE).stdout.decode(
                "utf-8"
            )
            _logger.debug(f"run command [{' '.join(command)}]")
            _logger.debug(f"got output \n {out_put}")
            return out_put
        except CalledProcessError as e:
            _logger.debug(
                f"{e.cmd} error_code: {e.returncode} error_msg: {e.stderr} output: {e.stdout}"
            )
            raise e

    def get_peers(
        self,
        vrf: Optional[str] = None,
    ):
        data = jc.parse("ntpq", self.run_command(["-p", "-n"], vrf=vrf))
        _logger.debug(f"parsed data :: {data}")
        return data

    def get_rv(self, vrf: Optional[str] = None):
        rv = {}
        output = self.run_command(["-c", "rv"], vrf=vrf)
        for element in output.replace("\n", "").split(","):
            try:
                key, value = element.strip().split("=", maxsplit=1)
                rv[key] = value.replace('"', "")
            except ValueError:
                _logger.debug(f"[{element}] is not '=' separated")
                continue
        return rv


class NtpCollector:
    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [
                thread_pool.submit(self.export_ntp_global),
                thread_pool.submit(self.export_ntp_server),
                thread_pool.submit(self.export_ntp_peers),
            ],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(f"Time taken in metrics collection {datetime.now() - date_time}")
        yield self.metric_ntp_peers
        yield self.metric_ntp_sync_status
        yield self.metric_ntp_when
        yield self.metric_ntp_rtd
        yield self.metric_ntp_offset
        yield self.metric_ntp_jitter
        yield self.metric_ntp_global
        yield self.metric_ntp_server

    def __init_metrics(self):
        self.metric_ntp_peers = GaugeMetricFamily(
            "sonic_ntp_peers",
            "NTP peers",
            labels=["remote", "refid", "st", "t", "poll", "reach", "state"],
        )

        self.metric_ntp_sync_status = GaugeMetricFamily(
            "sonic_ntp_sync_status",
            "SONiC NTP Sync Status (0/1 0==Not in Sync 1==Sync)",
        )
        self.metric_ntp_when = GaugeMetricFamily(
            "sonic_ntp_when",
            "Time (in seconds) since an NTP packet update was received",
            labels=["remote", "refid"],
        )

        self.metric_ntp_rtd = GaugeMetricFamily(
            "sonic_ntp_rtd",
            "Round-trip delay (in milliseconds) to the NTP server.",
            labels=["remote", "refid"],
        )

        self.metric_ntp_offset = GaugeMetricFamily(
            "sonic_ntp_offset",
            "Time difference (in milliseconds) between the switch and the NTP server or another NTP peer.",
            labels=["remote", "refid"],
        )

        self.metric_ntp_jitter = GaugeMetricFamily(
            "sonic_ntp_jitter",
            "Mean deviation in times between the switch and the NTP server",
            labels=["remote", "refid"],
        )

        self.metric_ntp_global = GaugeMetricFamily(
            "sonic_ntp_global",
            "NTP Global",
            labels=["vrf", "auth_enabled", "src_intf", "trusted_key"],
        )

        self.metric_ntp_server = GaugeMetricFamily(
            "sonic_ntp_server",
            "NTP Servers",
            labels=["ntp_server", "key_id", "minpoll", "maxpoll"],
        )

    def export_ntp_global(self):
        dict = getAllFromDB(sonic_db.CONFIG_DB, "NTP|global")
        if dict:
            self.metric_ntp_global.add_metric(
                [
                    dict.get("vrf") if "vrf" in dict else "",
                    dict.get("auth_enabled") if "auth_enabled" in dict else "",
                    dict.get("src_intf@") if "src_intf@" in dict else "",
                    dict.get("trusted_key@") if "trusted_key@" in dict else "",
                ],
                1,
            )

    def export_ntp_server(self):
        for key in getKeysFromDB(sonic_db.CONFIG_DB, NTP_SERVER_PATTERN):
            dict = getAllFromDB(sonic_db.CONFIG_DB, key)
            if dict:
                self.metric_ntp_server.add_metric(
                    [
                        key.split("|")[1],
                        dict.get("key_id") if "key_id" in dict else "",
                        dict.get("minpoll") if "minpoll" in dict else "",
                        dict.get("maxpoll") if "maxpoll" in dict else "",
                    ],
                    1,
                )

    def export_ntp_peers(self):
        vrf = getFromDB(
            sonic_db.CONFIG_DB, "MGMT_VRF_CONFIG|vrf_global", "mgmtVrfEnabled"
        )
        peers = NTPQ().get_peers(vrf=vrf)
        ntp_rv = NTPQ().get_rv(vrf=vrf)
        ntp_status = ntp_rv.get("associd", "")
        if "leap_none" in ntp_status:
            self.metric_ntp_sync_status.add_metric([], 1.0)
        else:
            self.metric_ntp_sync_status.add_metric([], 0)
        for op in peers:
            _logger.debug(
                f"export_ntp_peers :: {' '.join([f'{key}={value}' for key, value in op.items()])}"
            )
            self.metric_ntp_peers.add_metric(
                [
                    op.get("remote"),
                    op.get("refid"),
                    str(op.get("st")),
                    op.get("t"),
                    str(op.get("poll")),
                    str(op.get("reach")),
                    " " if op.get("state") is None else op.get("state"),
                ],
                1,
            )
            self.metric_ntp_jitter.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("jitter"))
            )
            self.metric_ntp_offset.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("offset"))
            )
            self.metric_ntp_rtd.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("delay"))
            )
            self.metric_ntp_when.add_metric(
                [op.get("remote"), op.get("refid")], floatify(op.get("when"))
            )


if __name__ == "__main__":
    import json
    from .test.mock_ntpq import MockNTPQ

    print(json.dumps(MockNTPQ().get_peers(), indent=2))
    print(json.dumps(MockNTPQ().get_rv(), indent=2))
    print(json.dumps(NTPQ().get_peers(), indent=2))
    print(json.dumps(NTPQ().get_rv(), indent=2))
