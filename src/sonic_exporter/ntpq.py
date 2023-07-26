import jc
import logging
from subprocess import PIPE, CalledProcessError, run
from typing import Optional
from sonic_exporter.constants import NTP_SERVER_PATTERN

from sonic_exporter.converters import floatify
from sonic_exporter.db_util import getAllFromDB, getFromDB, getKeysFromDB,sonic_db
from prometheus_client.core import GaugeMetricFamily



_logger = logging.getLogger(__name__)

metric_ntp_peers = GaugeMetricFamily(
    "sonic_ntp_peers",
    "NTP peers",
    labels=["remote", "refid", "st", "t", "poll", "reach", "state"],
)

metric_ntp_sync_status = GaugeMetricFamily(
            "sonic_ntp_sync_status",
            "SONiC NTP Sync Status (0/1 0==Not in Sync 1==Sync)",
)
metric_ntp_when = GaugeMetricFamily(
    "sonic_ntp_when",
    "Time (in seconds) since an NTP packet update was received",
    labels=["remote", "refid"],
)

metric_ntp_rtd = GaugeMetricFamily(
    "sonic_ntp_rtd",
    "Round-trip delay (in milliseconds) to the NTP server.",
    labels=["remote", "refid"],
)

metric_ntp_offset = GaugeMetricFamily(
    "sonic_ntp_offset",
    "Time difference (in milliseconds) between the switch and the NTP server or another NTP peer.",
    labels=["remote", "refid"],
)

metric_ntp_jitter = GaugeMetricFamily(
    "sonic_ntp_jitter",
    "Mean deviation in times between the switch and the NTP server",
    labels=["remote", "refid"],
)

metric_ntp_global = GaugeMetricFamily(
    "sonic_ntp_global",
    "NTP Global",
    labels=["vrf", "auth_enabled", "src_intf", "trusted_key"],
)

metric_ntp_server = GaugeMetricFamily(
    "sonic_ntp_server",
    "NTP Servers",
    labels=["ntp_server", "key_id", "minpoll", "maxpoll"],
)



def run_command(command: list, vrf: Optional[str] = None):
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
        _logger.debug(f"run command [{' '.join(command)}]")
        _logger.debug(f"got output \n {out_put}")
        return out_put
    except CalledProcessError as e:
        _logger.debug(
            f"{e.cmd} error_code: {e.returncode} error_msg: {e.stderr} output: {e.stdout}"
        )
        raise e

def get_peers(
    vrf: Optional[str] = None,
):
    data = jc.parse("ntpq", run_command(["-p", "-n"], vrf=vrf))
    _logger.debug(f"parsed data :: {data}")
    return data

def get_rv(vrf: Optional[str] = None):
    rv = {}
    output = run_command(["-c", "rv"], vrf=vrf)
    for element in output.replace("\n", "").split(","):
        try:
            key, value = element.strip().split("=", maxsplit=1)
            rv[key] = value.replace('"', "")
        except ValueError:
            _logger.debug(f"[{element}] is not '=' separated")
            continue
    return rv



def export_ntp_global():
    dict =getAllFromDB(sonic_db.CONFIG_DB, "NTP|global")
    if dict:
        metric_ntp_global.add_metric(
            [
                dict.get("vrf") if "vrf" in dict else "",
                dict.get("auth_enabled") if "auth_enabled" in dict else "",
                dict.get("src_intf@") if "src_intf@" in dict else "",
                dict.get("trusted_key@") if "trusted_key@" in dict else "",
            ],
            1,
        )

def export_ntp_server():
    for key in getKeysFromDB(sonic_db.CONFIG_DB, NTP_SERVER_PATTERN):
        dict = getAllFromDB(sonic_db.CONFIG_DB, key)
        if dict:
            metric_ntp_server.add_metric(
                [
                    key.split("|")[1],
                    dict.get("key_id") if "key_id" in dict else "",
                    dict.get("minpoll") if "minpoll" in dict else "",
                    dict.get("maxpoll") if "maxpoll" in dict else "",
                ],
                1,
            )

def export_ntp_peers():
    vrf = getFromDB(
        sonic_db.CONFIG_DB, "NTP|global", "vrf", retries=0, timeout=0
    )
    peers = get_peers(vrf=vrf)
    ntp_rv = get_rv(vrf=vrf)
    ntp_status = ntp_rv.get("associd", "")
    if "leap_none" in ntp_status:
        metric_ntp_sync_status.add_metric([], 1.0)
    else:
        metric_ntp_sync_status.add_metric([], 0)
    _logger.debug(f"hello {json.dumps(peers, indent=2)}")
    for op in peers:
        _logger.debug(
            f"export_ntp_peers :: {' '.join([f'{key}={value}' for key, value in op.items()])}"
        )
        metric_ntp_peers.add_metric(
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
        metric_ntp_jitter.add_metric(
            [op.get("remote"), op.get("refid")], floatify(op.get("jitter"))
        )
        metric_ntp_offset.add_metric(
            [op.get("remote"), op.get("refid")], floatify(op.get("offset"))
        )
        metric_ntp_rtd.add_metric(
            [op.get("remote"), op.get("refid")], floatify(op.get("delay"))
        )
        metric_ntp_when.add_metric(
            [op.get("remote"), op.get("refid")], floatify(op.get("when"))
        )



if __name__ == "__main__":
    import json
    from .test.mock_ntpq import MockNTPQ

    print(json.dumps(MockNTPQ().get_peers(), indent=2))
    print(json.dumps(MockNTPQ().get_rv(), indent=2))
    print(json.dumps(get_peers(), indent=2))
    print(json.dumps(get_rv(), indent=2))
