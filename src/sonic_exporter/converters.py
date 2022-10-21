import datetime
import time
from typing import Optional, Union

from sonic_exporter.constants import TRUE_VALUES


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
    if hasattr(string, "decode"):
        return string.decode("utf-8")
    if string is None:
        return ""
    return string


def to_timestamp(data: Union[int, float]) -> float:
    assert isinstance(data, (int, float))
    delta = datetime.timedelta(seconds=data)
    now = datetime.datetime.now(datetime.timezone.utc)
    uptime = get_uptime()
    timing = now - uptime + delta
    return timing.replace(tzinfo=datetime.timezone.utc).timestamp()
