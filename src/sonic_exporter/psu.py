import logging
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.core import GaugeMetricFamily
from constants import PSU_INFO, PSU_INFO_PATTERN
from db_util import ConfigDBVersion, getFromDB, db_version, getKeysFromDB
from sonic_exporter.converters import boolify, decode as _decode, floatify
from db_util import sonic_db

_logger = logging.getLogger(__name__)

metric_device_psu_input_volts = GaugeMetricFamily(
    "sonic_device_psu_input_volts",
    "The Amount of Voltage provided to the power supply",
    labels=["slot"],
)
metric_device_psu_input_amperes = GaugeMetricFamily(
    "sonic_device_psu_input_amperes",
    "The Amount of Amperes provided to the power supply",
    labels=["slot"],
)
metric_device_psu_output_volts = GaugeMetricFamily(
    "sonic_device_psu_output_volts",
    "The Amount of Voltage provided to the internal system",
    labels=["slot"],
)
metric_device_psu_output_amperes = GaugeMetricFamily(
    "sonic_device_psu_output_amperes",
    "The Amount of Amperes used by the system",
    labels=["slot"],
)
metric_device_psu_operational_status = GaugeMetricFamily(
    "sonic_device_psu_operational_status",
    "Shows if a power supply is Operational (0(DOWN)/1(UP))",
    labels=["slot"],
)
metric_device_psu_available_status = GaugeMetricFamily(
    "sonic_device_psu_available_status",
    "Shows if a power supply is plugged in (0(DOWN)/1(UP))",
    labels=["slot"],
)
metric_device_psu_celsius = GaugeMetricFamily(
    "sonic_device_psu_celsius",
    "The Temperature in Celsius of the PSU",
    labels=["slot"],
)
metric_device_psu_info = GaugeMetricFamily(
    "sonic_device_psu_info",
    "More information of the psu",
    labels=["slot", "serial", "model_name", "model"],
)


def export_psu_info():
    keys = getKeysFromDB(sonic_db.STATE_DB, PSU_INFO_PATTERN)
    if not keys:
        return
    for key in keys:
        serial = _decode(getFromDB(sonic_db.STATE_DB, key, "serial")).strip()
        available_status = _decode(getFromDB(sonic_db.STATE_DB, key, "presence"))
        operational_status = _decode(getFromDB(sonic_db.STATE_DB, key, "status"))
        model = _decode(getFromDB(sonic_db.STATE_DB, key, "model")).strip()
        model_name = _decode(getFromDB(sonic_db.STATE_DB, key, "name"))
        _, slot = _decode(key.replace(PSU_INFO, "")).lower().split(" ")
        try:
            in_volts = floatify(getFromDB(sonic_db.STATE_DB, key, "input_voltage"))
            in_amperes = floatify(getFromDB(sonic_db.STATE_DB, key, "input_current"))
            metric_device_psu_input_amperes.add_metric([slot], in_amperes)
            metric_device_psu_input_volts.add_metric([slot], in_volts)
            _logger.debug(
                f"export_psu_info :: slot={slot}, in_amperes={in_amperes}, in_volts={in_volts}"
            )
        except ValueError:
            pass
        try:
            out_volts = floatify(getFromDB(sonic_db.STATE_DB, key, "output_voltage"))
            out_amperes = floatify(getFromDB(sonic_db.STATE_DB, key, "output_current"))
            metric_device_psu_output_amperes.add_metric([slot], out_amperes)
            metric_device_psu_output_volts.add_metric([slot], out_volts)
            _logger.debug(
                f"export_psu_info :: slot={slot}, out_amperes={out_amperes}, out_volts={out_volts}"
            )
        except ValueError:
            pass
        try:
            temperature = float("-Inf")
            if db_version < ConfigDBVersion("version_4_0_0"):
                temperature = floatify(getFromDB(sonic_db.STATE_DB, key, "temperature"))
            else:
                temperature = floatify(getFromDB(sonic_db.STATE_DB, key, "temp"))
            metric_device_psu_celsius.add_metric([slot], temperature)
        except ValueError:
            pass
        metric_device_psu_available_status.add_metric([slot], boolify(available_status))
        metric_device_psu_operational_status.add_metric(
            [slot], boolify(operational_status)
        )
        metric_device_psu_info.add_metric([slot, serial, model_name, model], 1)
