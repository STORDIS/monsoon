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

import jc
from typing import Optional
from sonic_exporter.ntpq import NTPQ


class MockNTPQ(NTPQ):
    def run_command(self, command: list, vrf: Optional[str] = None):
        out_put: str = ""
        if ["-p", "-n"] == command:
            ## TODO: Put local VRF commands into their own module
            out_put = """     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
+10.90.221.13    .DCFa.           1 u  185  512  377    9.797    2.247   0.306
*10.90.221.29    .DCFa.           1 u  450  512  377    7.097    1.271   0.797
-10.90.221.45    .DCFa.           1 u  256  512  377    8.495    1.111   0.420
+10.90.221.61    .DCFa.           1 u   16  512  377    7.949    0.388   0.278
-10.90.221.77    .DCFa.           1 u  191  512  377   18.269   -0.723   3.381
"""
        elif ["-c", "rv"] == command:
            out_put = """associd=0 status=0615 leap_none, sync_ntp, 1 event, clock_sync,
version="ntpd 4.2.8p10@1.3728-o Sun Jan 16 06:54:44 UTC 2022 (1)",
processor="x86_64", system="Linux/4.9.0-11-2-amd64", leap=00, stratum=2,
precision=-23, rootdelay=11.980, rootdisp=8.904, refid=172.22.13.11,
reftime=e75d3b39.13ff9105  Mon, Jan  2 2023 11:15:05.078,
clock=e75d3cc4.02824611  Mon, Jan  2 2023 11:21:40.009, peer=36615, tc=7,
mintc=3, offset=0.220245, frequency=6.429, sys_jitter=0.028152,
clk_jitter=0.641, clk_wander=0.007
"""
        else:
            raise NotImplementedError(f"This mock function is missing {command}")
        return out_put
