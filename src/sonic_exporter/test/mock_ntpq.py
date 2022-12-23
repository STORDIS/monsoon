import jc
from typing import Optional
from sonic_exporter.ntpq import NTPQ

from sonic_exporter.utilities import ConfigDBVersion


class MockNTPQ(NTPQ):
    def run_command(
        self, command: list, db_version: ConfigDBVersion, vrf: Optional[str] = None
    ):
        ## TODO: Put local VRF commands into their own module
        out_put = """     remote           refid      st t when poll reach   delay   offset  jitter
==============================================================================
+10.90.221.13    .DCFa.           1 u  185  512  377    9.797    2.247   0.306
*10.90.221.29    .DCFa.           1 u  450  512  377    7.097    1.271   0.797
-10.90.221.45    .DCFa.           1 u  256  512  377    8.495    1.111   0.420
+10.90.221.61    .DCFa.           1 u   16  512  377    7.949    0.388   0.278
-10.90.221.77    .DCFa.           1 u  191  512  377   18.269   -0.723   3.381
"""
        return jc.parse("ntpq", out_put, raw=True)
