from datetime import datetime
from typing import Union
import datetime
import time
from sonic_exporter.constants import TRUE_VALUES


def boolify(data: str) -> bool:
    if data.lower() in TRUE_VALUES:
        return True
    return False


def floatify(data: Union[str, float, int, bool]) -> float:
    if isinstance(data, bool):
        if data:
            return float(1)
        else:
            print(f"{data} is bool")
            return float(0)
    return float(data)


def get_uptime() -> datetime.timedelta:
    return datetime.timedelta(seconds=time.clock_gettime(time.CLOCK_MONOTONIC))


def to_timestamp(data: Union[int, float]) -> float:
    assert isinstance(data, (int, float))
    delta = datetime.timedelta(seconds=data)
    now = datetime.datetime.now(datetime.timezone.utc)
    uptime = get_uptime()
    timing = now - uptime + delta
    return timing.replace(tzinfo=datetime.timezone.utc).timestamp()
