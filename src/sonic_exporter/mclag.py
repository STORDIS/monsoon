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
from prometheus_client.core import GaugeMetricFamily
from .utilities import get_logger, thread_pool

from .constants import (
    MCLAG_DOMAIN,
    MCLAG_DOMAIN_PATTERN,
    MCLAG_TABLE,
    MCLAG_TABLE_PATTERN,
)
from .db_util import getAllFromDB, getKeysFromDB, sonic_db
from .converters import decode

_logger = get_logger().getLogger(__name__)


class MclagCollector(object):
    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [
                thread_pool.submit(self.export_mclag_domain),
                thread_pool.submit(self.export_mclag_oper_state),
            ],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(f"Time taken in metrics collection {datetime.now() - date_time}")
        yield self.metric_mclag_domain
        yield self.metric_mclag_oper_state

    def __init_metrics(self):
        self.metric_mclag_domain = GaugeMetricFamily(
            "sonic_mclag_domain",
            "MCLAG Domain",
            labels=[
                "domain_id",
                "source_ip",
                "keepalive_interval",
                "session_timeout",
                "peer_ip",
                "peer_link",
                "mclag_system_mac",
            ],
        )

        self.metric_mclag_oper_state = GaugeMetricFamily(
            "sonic_mclag_oper_state",
            "MCLAG Operational State",
            labels=[
                "domain_id",
                "mclag_system_mac",
                "role",
                "system_mac",
                "peer_mac",
                "reason",
            ],
        )

    def export_mclag_domain(self):
        mclag_domain = {
            decode(key).replace(MCLAG_DOMAIN, ""): getAllFromDB(sonic_db.CONFIG_DB, key)
            for key in getKeysFromDB(sonic_db.CONFIG_DB, MCLAG_DOMAIN_PATTERN)
        }
        if mclag_domain and mclag_domain is not None:
            for domain_id, domain_attr in mclag_domain.items():
                source_ip = domain_attr.get("source_ip", "")
                keepalive_interval = domain_attr.get("keepalive_interval", "")
                session_timeout = domain_attr.get("session_timeout", "")
                peer_ip = domain_attr.get("peer_ip", "")
                peer_link = domain_attr.get("peer_link", "")
                mclag_system_mac = domain_attr.get("mclag_system_mac", "")
                self.metric_mclag_domain.add_metric(
                    [
                        domain_id,
                        "" if not source_ip else source_ip,
                        "" if not keepalive_interval else str(keepalive_interval),
                        "" if not session_timeout else str(session_timeout),
                        "" if not peer_ip else peer_ip,
                        "" if not peer_link else peer_link,
                        "" if not mclag_system_mac else mclag_system_mac,
                    ],
                    1,
                )

    def export_mclag_oper_state(self):
        mclag_state = {
            decode(key).replace(MCLAG_TABLE, ""): getAllFromDB(sonic_db.STATE_DB, key)
            for key in getKeysFromDB(sonic_db.STATE_DB, MCLAG_TABLE_PATTERN)
        }
        if mclag_state and mclag_state is not None:
            for domain_id, domain_state_attr in mclag_state.items():
                mclag_system_mac = domain_state_attr.get("mclag_system_mac", "")
                role = domain_state_attr.get("role", "")
                system_mac = domain_state_attr.get("system_mac", "")
                peer_mac = domain_state_attr.get("peer_mac", "")
                oper_status = (
                    1 if domain_state_attr.get("oper_status", "") == "up" else 0
                )
                reason = domain_state_attr.get("reason", "")
                self.metric_mclag_oper_state.add_metric(
                    [
                        domain_id,
                        "" if not mclag_system_mac else mclag_system_mac,
                        "" if not role else role,
                        "" if not system_mac else system_mac,
                        "" if not peer_mac else peer_mac,
                        "" if not reason else reason,
                    ],
                    oper_status,
                )
