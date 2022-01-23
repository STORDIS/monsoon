from typing import Union

from sonic_exporter.constants import TRUE_VALUES
def boolify(data: str) -> bool:
    if data in TRUE_VALUES:
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
