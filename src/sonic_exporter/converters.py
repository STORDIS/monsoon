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

import datetime
import time
from typing import Optional, Union

from .constants import TRUE_VALUES


def boolify(data: Union[str, bool]) -> bool:
    if isinstance(data, bool):
        return data
    elif data is None:
        return False
    elif data.lower() in TRUE_VALUES:
        return True
    else:
        return False


def floatify(data: Optional[Union[str, float, int, bool]]) -> float:
    match data:
        case True:
            return float(1)
        case False:
            return float(0)
        case None:
            return float(0)
        case _:
            return float(data)


def get_uptime() -> datetime.timedelta:
    return datetime.timedelta(seconds=time.clock_gettime(time.CLOCK_MONOTONIC))


def decode(string: Union[bytes, str, None]) -> str:
    match string:
        case bytes():
            return string.decode("utf-8")
        case str():
            return string
        case None:
            return ""
    return ""


def to_timestamp(data: Union[int, float]) -> float:
    assert isinstance(data, (int, float))
    delta = datetime.timedelta(seconds=data)
    now = datetime.datetime.now(datetime.timezone.utc)
    uptime = get_uptime()
    timing = now - uptime + delta
    return timing.replace(tzinfo=datetime.timezone.utc).timestamp()
