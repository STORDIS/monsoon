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
import re
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

from .utilities import get_logger, thread_pool
from .constants import (
    COUNTER_IGNORE,
    COUNTER_PORT_MAP,
    COUNTER_QUEUE_MAP,
    COUNTER_QUEUE_TYPE_MAP,
    COUNTER_TABLE_PREFIX,
    PORT_TABLE_PREFIX,
    TRANSCEIVER_DOM_SENSOR,
    TRANSCEIVER_DOM_SENSOR_PATTERN,
    TRANSCEIVER_INFO,
    TRANSCEIVER_INFO_PATTERN,
)
from .db_util import (
    ConfigDBVersion,
    getAllFromDB,
    getFromDB,
    db_version,
    getKeysFromDB,
    sonic_db,
)
from .converters import boolify, decode as _decode, floatify, to_timestamp

_logger = get_logger().getLogger(__name__)


rx_power_regex = re.compile(r"^rx(\d*)power$")
tx_power_regex = re.compile(r"^tx(\d*)power$")
tx_bias_regex = re.compile(r"^tx(\d*)bias$")


def get_counter_key(name: str) -> str:
    return f"{COUNTER_TABLE_PREFIX}{name}"


def get_additional_info(ifname):
    return get_portinfo(ifname, "alias") or ifname


def get_portinfo(ifname, sub_key):
    if ifname.startswith("Ethernet"):
        key = f"PORT|{ifname}"
    else:
        key = f"PORTCHANNEL|{ifname}"
    try:
        return _decode(getFromDB(sonic_db.CONFIG_DB, key, sub_key))
    except (ValueError, KeyError):
        return ""


def get_port_table_key(name: str) -> str:
    if name.startswith("PortChannel"):
        raise ValueError(f"{name} is not a physical interface")
    return f"{PORT_TABLE_PREFIX}{name}"


class InterfaceCollector(object):
    def collect(self):
        date_time = datetime.now()
        self.__init_metrics()
        wait(
            [
                thread_pool.submit(self.export_interface_counters),
                thread_pool.submit(self.export_interface_queue_counters),
                thread_pool.submit(self.export_interface_optic_data),
                thread_pool.submit(self.export_interface_cable_data),
            ],
            return_when=ALL_COMPLETED,
        )

        _logger.debug(f"Time taken in metrics collection {datetime.now() - date_time}")
        yield self.metric_interface_transceiver_info
        yield self.metric_interface_cable_length_meters
        yield self.metric_transceiver_threshold_info
        yield self.metric_interface_info
        yield self.metric_interface_speed
        yield self.metric_interface_transmitted_bytes
        yield self.metric_interface_received_bytes
        yield self.metric_interface_transmitted_packets
        yield self.metric_interface_received_packets
        yield self.metric_interface_receive_error_input_packets
        yield self.metric_interface_transmit_error_output_packets
        yield self.metric_interface_received_ethernet_packets
        yield self.metric_interface_transmitted_ethernet_packets
        # Interface Status Gauges
        yield self.metric_interface_operational_status
        yield self.metric_interface_admin_status
        yield self.metric_interface_last_flapped_seconds
        # Queue Counters
        yield self.metric_interface_queue_processed_packets
        yield self.metric_interface_queue_processed_bytes
        # Optic Health Information
        yield self.metric_interface_receive_optic_power_dbm
        yield self.metric_interface_transmit_optic_power_dbm
        yield self.metric_interface_transmit_optic_bias_amperes
        yield self.metric_interface_optic_celsius
        yield self.metric_interface_optic_volts

    def __init_metrics(self):
        interface_labels = ["interface"]
        port_label = ["port"]
        self.metric_interface_transceiver_info = GaugeMetricFamily(
            "sonic_interface_transceiver_info",
            "General Information about the transceivers per Interface",
            labels=interface_labels
            + [
                "serial",
                "part_number",
                "revision",
                "formfactor",
                "connector_type",
                "display_name",
                "media_interface",
            ],
        )

        self.metric_interface_cable_length_meters = GaugeMetricFamily(
            "sonic_interface_cable_length_meters",
            "The length of the plugged in Cable",
            labels=interface_labels + ["cable_type", "connector_type"],
        )

        self.metric_transceiver_threshold_info = GaugeMetricFamily(
            "sonic_transceiver_threshold_info",
            "Thresholds info for the transceivers inserted",
            labels=port_label
            + interface_labels
            + [
                "vcchighalarm",
                "vcchighwarning",
                "vcclowalarm",
                "vcclowwarning",
                "temphighalarm",
                "temphighwarning",
                "templowalarm",
                "templowwarning",
                "txbiashighalarm",
                "txbiashighwarning",
                "txbiaslowalarm",
                "txbiaslowwarning",
                "txpowerhighalarm",
                "txpowerhighwarning",
                "txpowerlowalarm",
                "txpowerlowwarning",
                "rxpowerhighalarm",
                "rxpowerhighwarning",
                "rxpowerlowalarm",
                "rxpowerlowwarning",
            ],
        )
        self.metric_interface_info = GaugeMetricFamily(
            "sonic_interface_info",
            "Interface Information (Description, MTU, Speed)",
            labels=interface_labels + ["description", "mtu", "speed", "device"],
        )
        self.metric_interface_speed = GaugeMetricFamily(
            "sonic_interface_speed_bytes",
            "The maximum interface speed in bytes per second",
            labels=interface_labels,
        )
        self.metric_interface_transmitted_bytes = CounterMetricFamily(
            "sonic_interface_transmitted_bytes_total",
            "Total transmitted Bytes by Interface",
            labels=interface_labels,
        )
        self.metric_interface_received_bytes = CounterMetricFamily(
            "sonic_interface_received_bytes_total",
            "Total received Bytes by Interface",
            labels=interface_labels,
        )
        self.metric_interface_transmitted_packets = CounterMetricFamily(
            "sonic_interface_transmitted_packets_total",
            "Total transmitted Packets by Interface",
            labels=interface_labels + ["delivery_mode"],
        )
        self.metric_interface_received_packets = CounterMetricFamily(
            "sonic_interface_received_packets_total",
            "Total received Packets by Interface",
            labels=interface_labels + ["delivery_mode"],
        )
        self.metric_interface_receive_error_input_packets = CounterMetricFamily(
            "sonic_interface_receive_error_input_packets_total",
            "Errors in received packets",
            labels=interface_labels + ["cause"],
        )
        self.metric_interface_transmit_error_output_packets = CounterMetricFamily(
            "sonic_interface_transmit_error_output_packets_total",
            "Errors in transmitted packets",
            labels=interface_labels + ["cause"],
        )
        self.metric_interface_received_ethernet_packets = CounterMetricFamily(
            "sonic_interface_received_ethernet_packets_total",
            "Size of the Ethernet Frames received",
            labels=interface_labels + ["packet_size"],
        )
        self.metric_interface_transmitted_ethernet_packets = CounterMetricFamily(
            "sonic_interface_transmitted_ethernet_packets_total",
            "Size of the Ethernet Frames transmitted",
            labels=interface_labels + ["packet_size"],
        )
        # Interface Status Gauges
        self.metric_interface_operational_status = GaugeMetricFamily(
            "sonic_interface_operational_status",
            "The Operational Status reported from the Device (0(DOWN)/1(UP))",
            labels=interface_labels,
        )
        self.metric_interface_admin_status = GaugeMetricFamily(
            "sonic_interface_admin_status",
            "The Configuration Status reported from the Device (0(DOWN)/1(UP))",
            labels=interface_labels,
        )
        self.metric_interface_last_flapped_seconds = CounterMetricFamily(
            "sonic_interface_last_flapped_seconds_total",
            "The Timestamp as Unix Timestamp since the last flap of the interface.",
            labels=interface_labels,
        )
        # Queue Counters
        self.metric_interface_queue_processed_packets = CounterMetricFamily(
            "sonic_interface_queue_processed_packets_total",
            "Interface queue counters",
            labels=interface_labels + ["queue"] + ["delivery_mode"],
        )
        self.metric_interface_queue_processed_bytes = CounterMetricFamily(
            "sonic_interface_queue_processed_bytes_total",
            "Interface queue counters",
            labels=interface_labels + ["queue"] + ["delivery_mode"],
        )
        # Optic Health Information
        self.metric_interface_receive_optic_power_dbm = GaugeMetricFamily(
            "sonic_interface_receive_optic_power_dbm",
            "Power value for all the interfaces",
            labels=port_label + interface_labels + ["optic_unit"],
        )
        self.metric_interface_transmit_optic_power_dbm = GaugeMetricFamily(
            "sonic_interface_transmit_optic_power_dbm",
            "Power value for all the interfaces",
            labels=port_label + interface_labels + ["optic_unit"],
        )
        self.metric_interface_transmit_optic_bias_amperes = GaugeMetricFamily(
            "sonic_interface_transmit_optic_bias_amperes",
            "Transmit Bias Current for all optics in the interface",
            labels=port_label + interface_labels + ["optic_unit"],
        )
        self.metric_interface_optic_celsius = GaugeMetricFamily(
            "sonic_interface_optic_celsius",
            "Temperature for all interfaces",
            labels=port_label + interface_labels,
        )
        self.metric_interface_optic_volts = GaugeMetricFamily(
            "sonic_interface_optic_volts",
            "Voltage of all transceiver optics per interface",
            labels=port_label + interface_labels,
        )

    def export_interface_counters(self):
        maps = getAllFromDB(sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        for ifname in maps:
            counter_key = get_counter_key(_decode(maps[ifname]))
            ifname_decoded = _decode(ifname)
            # this should be GBit/s
            if ifname_decoded.lower() in COUNTER_IGNORE:
                continue
            interface_speed = (
                int(round(int(get_portinfo(ifname, "speed"))) / 1000)
                if get_portinfo(ifname, "speed")
                else 0
            )
            self.metric_interface_info.add_metric(
                [
                    get_additional_info(ifname),
                    get_portinfo(ifname, "description"),
                    get_portinfo(ifname, "mtu"),
                    f"{interface_speed}Gbps",
                    ifname,
                ],
                1,
            )
            self.metric_interface_speed.add_metric(
                [get_additional_info(ifname)],
                floatify(interface_speed * 1000 * 1000 * 1000 / 8),
            )

            # Ethernet RX
            for size, key in zip(
                (64, 127, 255, 511, 1023, 1518, 2047, 4095, 9216, 16383),
                (
                    "SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_2048_TO_4095_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_4096_TO_9216_OCTETS",
                    "SAI_PORT_STAT_ETHER_IN_PKTS_9217_TO_16383_OCTETS",
                ),
            ):
                self.metric_interface_received_ethernet_packets.add_metric(
                    [get_additional_info(ifname), str(size)],
                    floatify(
                        _decode(getFromDB(sonic_db.COUNTERS_DB, counter_key, key))
                    ),
                )
            # Ethernet TX
            for size, key in zip(
                (64, 127, 255, 511, 1023, 1518, 2047, 4095, 9216, 16383),
                (
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_2048_TO_4095_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_4096_TO_9216_OCTETS",
                    "SAI_PORT_STAT_ETHER_OUT_PKTS_9217_TO_16383_OCTETS",
                ),
            ):
                self.metric_interface_transmitted_ethernet_packets.add_metric(
                    [get_additional_info(ifname), str(size)],
                    floatify(
                        _decode(getFromDB(sonic_db.COUNTERS_DB, counter_key, key))
                    ),
                )
            # RX
            self.metric_interface_received_bytes.add_metric(
                [get_additional_info(ifname)],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_OCTETS",
                    )
                ),
            )
            self.metric_interface_received_packets.add_metric(
                [get_additional_info(ifname), "unicast"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                    )
                ),
            )
            self.metric_interface_received_packets.add_metric(
                [get_additional_info(ifname), "multicast"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS",
                    )
                ),
            )
            self.metric_interface_received_packets.add_metric(
                [get_additional_info(ifname), "broadcast"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS",
                    )
                ),
            )

            # RX Errors
            self.metric_interface_receive_error_input_packets.add_metric(
                [get_additional_info(ifname), "error"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_ERRORS",
                    )
                ),
            )
            self.metric_interface_receive_error_input_packets.add_metric(
                [get_additional_info(ifname), "discard"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_DISCARDS",
                    )
                ),
            )
            if db_version < ConfigDBVersion("version_4_0_0"):
                self.metric_interface_receive_error_input_packets.add_metric(
                    [get_additional_info(ifname), "drop"],
                    floatify(
                        getFromDB(
                            sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IN_DROPPED_PKTS",
                        )
                    ),
                )
            self.metric_interface_receive_error_input_packets.add_metric(
                [get_additional_info(ifname), "pause"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_RX_PKTS",
                    )
                ),
            )
            # TX
            self.metric_interface_transmitted_bytes.add_metric(
                [get_additional_info(ifname)],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_OCTETS",
                    )
                ),
            )
            self.metric_interface_transmitted_packets.add_metric(
                [get_additional_info(ifname), "unicast"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                    )
                ),
            )
            self.metric_interface_transmitted_packets.add_metric(
                [get_additional_info(ifname), "multicast"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS",
                    )
                ),
            )
            self.metric_interface_transmitted_packets.add_metric(
                [get_additional_info(ifname), "broadcast"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS",
                    )
                ),
            )
            # SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS
            # TX Errors
            self.metric_interface_transmit_error_output_packets.add_metric(
                [get_additional_info(ifname), "error"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_ERRORS",
                    )
                ),
            )
            self.metric_interface_transmit_error_output_packets.add_metric(
                [get_additional_info(ifname), "discard"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_DISCARDS",
                    )
                ),
            )
            self.metric_interface_transmit_error_output_packets.add_metric(
                [get_additional_info(ifname), "pause"],
                floatify(
                    getFromDB(
                        sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_PAUSE_TX_PKTS",
                    )
                ),
            )
            _logger.debug("export_intf_counter :: ifname={}".format(ifname))
            try:
                port_table_key = get_port_table_key(ifname)
                is_operational = _decode(
                    getFromDB(sonic_db.APPL_DB, port_table_key, "oper_status")
                )
                last_flapped_seconds = to_timestamp(
                    floatify(
                        _decode(
                            getFromDB(
                                sonic_db.APPL_DB,
                                port_table_key,
                                "oper_status_change_uptime",
                            )
                        )
                    )
                )
                is_admin = get_portinfo(ifname, "admin_status")
                self.metric_interface_operational_status.add_metric(
                    [get_additional_info(ifname)], boolify(is_operational)
                )
                self.metric_interface_admin_status.add_metric(
                    [get_additional_info(ifname)], boolify(is_admin)
                )
                self.metric_interface_last_flapped_seconds.add_metric(
                    [get_additional_info(ifname)], floatify(last_flapped_seconds)
                )
            except ValueError:
                pass

    def export_interface_queue_counters(self):
        maps = getAllFromDB(sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            decoded_counter_key = _decode(maps[ifname])
            counter_key = get_counter_key(decoded_counter_key)
            packet_type = _decode(
                getFromDB(
                    sonic_db.COUNTERS_DB,
                    COUNTER_QUEUE_TYPE_MAP,
                    decoded_counter_key,
                )
            )
            ifname = _decode(ifname)
            packets = getFromDB(
                sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_PACKETS",
            )
            bytes = getFromDB(
                sonic_db.COUNTERS_DB,
                counter_key,
                "SAI_QUEUE_STAT_BYTES",
            )
            queue_type = "N/A"
            ifname, queue = ifname.split(":")
            if ifname.lower() in COUNTER_IGNORE:
                continue
            if packet_type.endswith("MULTICAST"):
                queue_type = "multicast"
            if packet_type.endswith("UNICAST"):
                queue_type = "unicast"
            _logger.debug(
                "export_intf_queue_counters :: ifname={}, queue_type={}, packets={}".format(
                    ifname, queue_type, packets
                )
            )
            _logger.debug(
                "export_intf_queue_counters :: ifname={}, queue_type={}, bytes={}".format(
                    ifname, queue_type, bytes
                )
            )
            self.metric_interface_queue_processed_packets.add_metric(
                [get_additional_info(ifname), queue, queue_type], floatify(packets)
            )
            self.metric_interface_queue_processed_bytes.add_metric(
                [get_additional_info(ifname), queue, queue_type], floatify(bytes)
            )

    def export_interface_optic_data(self):
        keys = getKeysFromDB(sonic_db.STATE_DB, TRANSCEIVER_DOM_SENSOR_PATTERN)
        _logger.debug("export_interface_optic_data :: keys={}".format(keys))

        if not keys:
            return
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_DOM_SENSOR, "")
            transceiver_sensor_data = getAllFromDB(sonic_db.STATE_DB, key)

            vcchighalarm = vcchighwarning = vcclowalarm = vcclowwarning = (
                temphighalarm
            ) = temphighwarning = templowalarm = templowwarning = txbiashighalarm = (
                txbiashighwarning
            ) = txbiaslowalarm = txbiaslowwarning = txpowerhighalarm = (
                txpowerhighwarning
            ) = txpowerlowalarm = txpowerlowwarning = rxpowerhighalarm = (
                rxpowerhighwarning
            ) = rxpowerlowalarm = rxpowerlowwarning = "none"
            for measure in transceiver_sensor_data:
                measure_dec = _decode(measure)
                try:
                    value = transceiver_sensor_data[measure_dec]
                    match measure_dec:
                        case "voltage":
                            self.metric_interface_optic_volts.add_metric(
                                [ifname, get_additional_info(ifname)],
                                floatify(value),
                            )
                        case "vcchighalarm":
                            vcchighalarm = str(value)
                        case "vcchighwarning":
                            vcchighwarning = str(value)
                        case "vcclowalarm":
                            vcclowalarm = str(value)
                        case "vcclowwarning":
                            vcclowwarning = str(value)
                        case "temphighalarm":
                            temphighalarm = str(value)
                        case "temphighwarning":
                            temphighwarning = str(value)
                        case "templowalarm":
                            templowalarm = str(value)
                        case "templowwarning":
                            templowwarning = str(value)
                        case "txbiashighalarm":
                            txbiashighalarm = str(value)
                        case "txbiashighwarning":
                            txbiashighwarning = str(value)
                        case "txbiaslowalarm":
                            txbiaslowalarm = str(value)
                        case "txbiaslowwarning":
                            txbiaslowwarning = str(value)
                        case "txpowerhighalarm":
                            txpowerhighalarm = str(value)
                        case "txpowerhighwarning":
                            txpowerhighwarning = str(value)
                        case "txpowerlowalarm":
                            txpowerlowalarm = str(value)
                        case "txpowerlowwarning":
                            txpowerlowwarning = str(value)
                        case "rxpowerhighalarm":
                            rxpowerhighalarm = str(value)
                        case "rxpowerhighwarning":
                            rxpowerhighwarning = str(value)
                        case "rxpowerlowalarm":
                            rxpowerlowalarm = str(value)
                        case "rxpowerlowwarning":
                            rxpowerlowwarning = str(value)
                        case "temperature":
                            self.metric_interface_optic_celsius.add_metric(
                                [ifname, get_additional_info(ifname)],
                                floatify(value),
                            )
                        case _:
                            if match := rx_power_regex.fullmatch(measure_dec):
                                optic_unit = match.group(1)
                                self.metric_interface_receive_optic_power_dbm.add_metric(
                                    [
                                        ifname,
                                        get_additional_info(ifname),
                                        optic_unit,
                                    ],
                                    floatify(value),
                                )
                            elif match := tx_power_regex.fullmatch(measure_dec):
                                optic_unit = match.group(1)
                                self.metric_interface_transmit_optic_power_dbm.add_metric(
                                    [
                                        ifname,
                                        get_additional_info(ifname),
                                        optic_unit,
                                    ],
                                    floatify(value),
                                )
                            elif match := tx_bias_regex.fullmatch(measure_dec):
                                optic_unit = match.group(1)
                                # This resolves mA to Amperes
                                self.metric_interface_transmit_optic_bias_amperes.add_metric(
                                    [
                                        ifname,
                                        get_additional_info(ifname),
                                        optic_unit,
                                    ],
                                    floatify(value) / 1000,
                                )
                except ValueError as e:
                    pass
            self.metric_transceiver_threshold_info.add_metric(
                [
                    ifname,
                    get_additional_info(ifname),
                    vcchighalarm,
                    vcchighwarning,
                    vcclowalarm,
                    vcclowwarning,
                    temphighalarm,
                    temphighwarning,
                    templowalarm,
                    templowwarning,
                    txbiashighalarm,
                    txbiashighwarning,
                    txbiaslowalarm,
                    txbiaslowwarning,
                    txpowerhighalarm,
                    txpowerhighwarning,
                    txpowerlowalarm,
                    txpowerlowwarning,
                    rxpowerhighalarm,
                    rxpowerhighwarning,
                    rxpowerlowalarm,
                    rxpowerlowwarning,
                ],
                1,
            )

    def export_interface_cable_data(self):
        keys = getKeysFromDB(sonic_db.STATE_DB, TRANSCEIVER_INFO_PATTERN)
        if not keys:
            return
        for key in keys:
            ifname = _decode(key).replace(TRANSCEIVER_INFO, "")
            cable_type = ""
            if db_version < ConfigDBVersion("version_4_0_0"):
                cable_type = _decode(
                    str(getFromDB(sonic_db.STATE_DB, key, "Connector")).lower()
                )
            else:
                cable_type = _decode(
                    str(getFromDB(sonic_db.STATE_DB, key, "connector")).lower()
                )
            connector_type = _decode(
                str(getFromDB(sonic_db.STATE_DB, key, "connector_type"))
            ).lower()
            serial = _decode(getFromDB(sonic_db.STATE_DB, key, "vendor_serial_number"))
            part_number = _decode(
                getFromDB(sonic_db.STATE_DB, key, "vendor_part_number")
            )
            revision = _decode(getFromDB(sonic_db.STATE_DB, key, "vendor_revision"))
            form_factor = _decode(
                getFromDB(sonic_db.STATE_DB, key, "form_factor")
            ).lower()
            display_name = _decode(getFromDB(sonic_db.STATE_DB, key, "display_name"))
            media_interface = _decode(
                getFromDB(sonic_db.STATE_DB, key, "media_interface")
            ).lower()
            try:
                cable_len = floatify(getFromDB(sonic_db.STATE_DB, key, "cable_length"))
                self.metric_interface_cable_length_meters.add_metric(
                    [get_additional_info(ifname), cable_type, connector_type],
                    cable_len,
                )
            except ValueError:
                pass
            _logger.debug(
                f"export_interface_cable_data :: interface={get_additional_info(ifname)}"
            )
            self.metric_interface_transceiver_info.add_metric(
                [
                    get_additional_info(ifname),
                    serial,
                    part_number,
                    revision,
                    form_factor,
                    connector_type,
                    display_name,
                    media_interface,
                ],
                1,
            )
