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

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, ALL_COMPLETED, wait
from datetime import datetime

import prometheus_client as prom
from prometheus_client.core import REGISTRY

from .utilities import get_logger
from . import bgp
from . import crm
from . import evpn
from . import fan
from . import interface
from . import mclag
from . import ntpq
from . import psu
from . import sag
from . import system
from . import vxlan

from .db_util import is_sonic_sys_ready


_logger = get_logger().getLogger(__name__)


def check_sonic_ready():
    _logger.info("Checking if SONiC System is ready...")
    if not is_sonic_sys_ready(retries=15):
        _logger.error(
            "SONiC System isn't ready even after several retries, exiting sonic-exporter."
        )
        sys.exit(0)

    _logger.info("SONiC System is ready.")


def main():
    check_sonic_ready()
    port = int(
        os.environ.get("SONIC_EXPORTER_PORT", 9101)
    )  # setting port static as 9101. if required map it to someother port of host by editing compose file.
    address = str(os.environ.get("SONIC_EXPORTER_ADDRESS", "localhost"))

    _logger.info("Starting sonic-exporter at {}:{}".format(address, port))
    # TODO ip address validation
    prom.start_http_server(port, addr=address)
    REGISTRY.register(system.SystemCollector())
    REGISTRY.register(psu.PsuCollector())
    REGISTRY.register(vxlan.VxlanCollector())
    REGISTRY.register(sag.SagCollector())
    REGISTRY.register(ntpq.NtpCollector())
    REGISTRY.register(mclag.MclagCollector())
    REGISTRY.register(interface.InterfaceCollector())
    REGISTRY.register(fan.FanCollector())
    REGISTRY.register(evpn.EvpnCollector())
    REGISTRY.register(crm.CrmCollector())
    REGISTRY.register(bgp.BgpCollector())

    while True:
        time.sleep(10**8)


def cli():
    try:
        file_path = os.path.dirname(__file__)
        if file_path != "":
            os.chdir(file_path)
        main()
    except KeyboardInterrupt:
        sys.exit(0)
