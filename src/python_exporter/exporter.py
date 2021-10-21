import re
import json
import time
import prometheus_client as prom
import swsssdk
import os
import subprocess

COUNTER_PORT_MAP = "COUNTERS_PORT_NAME_MAP"
COUNTER_QUEUE_MAP = "COUNTERS_QUEUE_NAME_MAP"
COUNTER_QUEUE_TYPE_MAP = "COUNTERS_QUEUE_TYPE_MAP"
COUNTER_TABLE_PREFIX = "COUNTERS:"
STATUS_NA = "N/A"


def _decode(string):
    if hasattr(string, "decode"):
        return string.decode("utf-8")
    return string


class Export:
    def __init__(self):
        try :
            secret = os.environ.get('REDIS_AUTH')
            print(f"Password from ENV: {secret}")
        except :
            print ("Password env REDIS_AUTH is not set ... Exiting")
            sys.exit(1)

        self.sonic_db = swsssdk.SonicV2Connector(password=secret)
        self.sonic_db.connect(self.sonic_db.COUNTERS_DB)
        self.sonic_db.connect(self.sonic_db.STATE_DB)
        self.sonic_db.connect(self.sonic_db.CONFIG_DB)
        self.curr_time = time.time()
        self.rx_octets_dict = {}
        self.tx_octets_dict = {}
        self._init_metrics()

    def _init_metrics(self):
        self.counter_zero = {}
        self.queue_counter_zero = {}
        # at start of server get counters data and negate it with current data while exporting
        self.intf_counter_reset()
        self.intf_queue_counter_reset()

        self.metric_intf_util_bps = prom.Gauge(
            "python_interface_util_bps",
            "Interface current utilization",
            ["interface_name", "util_type"],
        )
        self.metric_intf_counter = prom.Gauge(
            "python_interface_counters_packets",
            "Interface Counters",
            ["interface_name", "counter_type"],
        )
        self.metric_intf_queue_counter = prom.Gauge(
            "python_interface_queue_counters_packets",
            "Interface queue counters",
            ["interface_name", "queue_type"],
        )
        self.metric_intf_err_counter = prom.Gauge(
            "python_interface_error_counters_packets",
            "RX_ERR and TX_ERR for all the interfaces",
            ["interface_name", "error_type"],
        )
        self.metric_intf_power = prom.Gauge(
            "python_interface_power_dbm",
            "Power value for all the interfaces",
            ["interface_name", "power_type"],
        )
        self.metric_intf_voltage = prom.Gauge(
            "python_interface_voltage_volts",
            "Voltage of all the interfaces",
            ["interface_name"],
        )
        self.metric_intf_temp = prom.Gauge(
            "python_interface_temperature_celsius",
            "Temperature of all the interfaces",
            ["interface_name"],
        )
        self.metric_intf_cable = prom.Gauge(
            "python_interface_cable_length",
            "Cable details for all the interfaces",
            ["interface_name", "cable_type"],
        )
        self.metric_psu = prom.Gauge(
            "python_env_power_usage_mw",
            "RX_OK and TX_OK for all the interfaces",
            ["psu_name", "power_type"],
        )
        self.sys_info = prom.Info(
            "python_system",
            "part name, serial number, MAC address and software vesion of the System",
        )

        self.metric_bgp_peer_status = prom.Enum(
            "python_bgp_peer_status",
            "Interface current utilization",
            ["peer_name", "status"],
            states=["up", "down"],
        )

        self.metric_bgp_num_routes = prom.Gauge(
            "python_bgp_num_routes",
            "Interface current utilization",
            ["peer_name"],
        )

        self.metric_system_top10_cpu_percent = prom.Gauge(
            "python_system_top10_cpu_percent",
            "system top10 process as per cpu percent",
            ["pid", "process_name"],
        )

        self.metric_system_top10_mem_percent = prom.Gauge(
            "python_system_top10_mem_percent",
            "system top10 process as per mem percent",
            ["pid", "process_name"],
        )

    # def _ns_diff(self, newstr, oldstr):
    #     """
    #         Calculate the diff.
    #     """
    #     if newstr == STATUS_NA or oldstr == STATUS_NA:
    #         return STATUS_NA
    #     else:
    #         new, old = int(newstr), int(oldstr)
    #         return '{:,}'.format(max(0, new - old))

    # def _ns_brate(self,newstr, oldstr, delta):
    #     """
    #         Calculate the byte rate.
    #     """
    #     if newstr == STATUS_NA or oldstr == STATUS_NA:
    #         return STATUS_NA
    #     else:
    #         rate = int(self._ns_diff(newstr, oldstr).replace(',',''))/delta
    #         return "{:.2f}".format(rate)

    def export_intf_util_bps(self, ifname, RX_OCTETS, TX_OCTETS, delta):
        RX_OCTETS_old = self.rx_octets_dict[ifname]
        TX_OCTETS_old = self.tx_octets_dict[ifname]
        # print(
        #     "export_intf_util_bps : ",
        #     ifname,
        #     RX_OCTETS,
        #     TX_OCTETS,
        #     RX_OCTETS_old,
        #     TX_OCTETS_old,
        #     delta,
        # )  # 12 12 487830 491425 10
        if RX_OCTETS > RX_OCTETS_old and delta != 0:
            rx_bps = round(((RX_OCTETS - RX_OCTETS_old) / delta), 2)
        else:
            rx_bps = 0
        if TX_OCTETS > TX_OCTETS_old and delta != 0:
            tx_bps = round(((TX_OCTETS - TX_OCTETS_old) / delta), 2)
        else:
            tx_bps = 0

        self.rx_octets_dict[ifname] = RX_OCTETS
        self.tx_octets_dict[ifname] = TX_OCTETS

        #print(rx_bps, tx_bps)

        self.metric_intf_util_bps.labels(ifname, "RX").set(rx_bps)
        self.metric_intf_util_bps.labels(ifname, "TX").set(tx_bps)

    def intf_counter_reset(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            try:
                self.counter_zero[ifname, "RX_OK"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                    )
                ) + int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "RX_OK"] = 0
            try:
                self.counter_zero[ifname, "TX_OK"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                    )
                ) + int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "TX_OK"] = 0
            try:
                self.counter_zero[ifname, "RX_ERR"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_IN_ERRORS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "RX_ERR"] = 0
            try:
                self.counter_zero[ifname, "TX_ERR"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB,
                        counter_key,
                        "SAI_PORT_STAT_IF_OUT_ERRORS",
                    )
                )
            except ValueError:
                self.counter_zero[ifname, "TX_ERR"] = 0

            self.rx_octets_dict[ifname] = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB, counter_key, "SAI_PORT_STAT_IF_IN_OCTETS"
                )
            )
            self.tx_octets_dict[ifname] = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    counter_key,
                    "SAI_PORT_STAT_IF_OUT_OCTETS",
                )
            )

    def intf_queue_counter_reset(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            try:
                self.queue_counter_zero[ifname, "QUEUE_STAT_PACKET"] = int(
                    self.sonic_db.get(
                        self.sonic_db.COUNTERS_DB, counter_key, "SAI_QUEUE_STAT_PACKETS"
                    )
                )
            except ValueError:
                self.queue_counter_zero[ifname, "QUEUE_STAT_PACKET"] = 0

    def export_intf_counter(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_PORT_MAP)
        old_time = self.curr_time
        print("old_time ", old_time)
        self.curr_time = time.time()
        print("self.curr_time ", self.curr_time)
        delta = int(self.curr_time - old_time)
        print("delta ", delta)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            ifname = _decode(ifname)
            try:
                RX_OK = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
                        )
                    )
                    + int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS",
                        )
                    )
                    - self.counter_zero[ifname, "RX_OK"]
                )
            except ValueError:
                RX_OK = 0
            try:
                TX_OK = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
                        )
                    )
                    + int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS",
                        )
                    )
                    - self.counter_zero[ifname, "TX_OK"]
                )
            except ValueError:
                TX_OK = 0
            try:
                RX_ERR = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_IN_ERRORS",
                        )
                    )
                    - self.counter_zero[ifname, "RX_ERR"]
                )
            except ValueError:
                RX_ERR = 0
            try:
                TX_ERR = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_PORT_STAT_IF_OUT_ERRORS",
                        )
                    )
                    - self.counter_zero[ifname, "TX_ERR"]
                )
            except ValueError:
                TX_ERR = 0

            RX_OCTETS = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB, counter_key, "SAI_PORT_STAT_IF_IN_OCTETS"
                )
            )
            TX_OCTETS = int(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    counter_key,
                    "SAI_PORT_STAT_IF_OUT_OCTETS",
                )
            )

            self.metric_intf_counter.labels(ifname, "RX_OK").set(RX_OK)
            self.metric_intf_counter.labels(ifname, "TX_OK").set(TX_OK)
            self.metric_intf_err_counter.labels(ifname, "RX").set(RX_ERR)
            self.metric_intf_err_counter.labels(ifname, "TX").set(TX_ERR)
            self.export_intf_util_bps(ifname, RX_OCTETS, TX_OCTETS, delta)
            # print(ifname, RX_OK, TX_OK, RX_ERR, TX_ERR)

    def export_intf_queue_counters(self):
        maps = self.sonic_db.get_all(self.sonic_db.COUNTERS_DB, COUNTER_QUEUE_MAP)
        for ifname in maps:
            counter_key = COUNTER_TABLE_PREFIX + _decode(maps[ifname])
            packet_type = _decode(
                self.sonic_db.get(
                    self.sonic_db.COUNTERS_DB,
                    COUNTER_QUEUE_TYPE_MAP,
                    _decode(maps[ifname]),
                )
            )
            ifname = _decode(ifname)
            try:
                QUEUE_STAT_PACKET = (
                    int(
                        self.sonic_db.get(
                            self.sonic_db.COUNTERS_DB,
                            counter_key,
                            "SAI_QUEUE_STAT_PACKETS",
                        )
                    )
                    - self.queue_counter_zero[ifname, "QUEUE_STAT_PACKET"]
                )
            except ValueError:
                QUEUE_STAT_PACKET = 0
            queue_type = "N/A"
            lane_no = ifname.split(":")[1]
            ifname = ifname.split(":")[0]
            if packet_type.endswith("MULTICAST"):
                queue_type = "MC" + lane_no
            if packet_type.endswith("UNICAST"):
                queue_type = "UC" + lane_no
            # print(ifname, queue_type, QUEUE_STAT_PACKET)
            self.metric_intf_queue_counter.labels(ifname, queue_type).set(
                QUEUE_STAT_PACKET
            )

    def export_intf_sensor_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern="*TRANSCEIVER_DOM_SENSOR*"
        )
        # print(keys)
        for key in keys:
            ifname = _decode(key).replace("TRANSCEIVER_DOM_SENSOR|", "")
            transceiver_sensor_data = self.sonic_db.get_all(self.sonic_db.STATE_DB, key)
            for measure in transceiver_sensor_data:
                measure_dec = _decode(measure)
                if bool(re.match("^rx[0-9]*power$", measure_dec)):
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_power.labels(ifname, measure_dec).set(
                            float(value)
                        )
                    except ValueError:
                        self.metric_intf_power.labels(ifname, measure_dec).set(0)
                if bool(re.match("^tx[0-9]*power$", measure_dec)):
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_power.labels(ifname, measure_dec).set(
                            float(value)
                        )
                    except ValueError:
                        self.metric_intf_power.labels(ifname, measure_dec).set(0)
                if measure_dec == "voltage":
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_voltage.labels(ifname).set(float(value))
                    except ValueError:
                        self.metric_intf_voltage.labels(ifname).set(0)
                if measure_dec == "temperature":
                    value = transceiver_sensor_data[measure]
                    try:
                        self.metric_intf_temp.labels(ifname).set(float(value))
                    except ValueError:
                        self.metric_intf_temp.labels(ifname).set(0)

    def export_intf_cable_data(self):
        keys = self.sonic_db.keys(
            self.sonic_db.STATE_DB, pattern="*TRANSCEIVER_INFO|Ethernet*"
        )
        for key in keys:
            ifname = _decode(key).replace("TRANSCEIVER_INFO|", "")
            CABLE_TYPE = _decode(
                self.sonic_db.get(self.sonic_db.STATE_DB, key, "Connector")
            )
            try:
                CABLE_LEN = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "cable_length")
                )
            except ValueError and TypeError:
                CABLE_LEN = 0
            self.metric_intf_cable.labels(ifname, CABLE_TYPE).set(CABLE_LEN)

    def export_psu_info(self):
        keys = self.sonic_db.keys(self.sonic_db.STATE_DB, pattern="PSU_INFO|PSU*")
        for key in keys:
            psu_name = _decode(self.sonic_db.get(self.sonic_db.STATE_DB, key, "name"))
            try:
                IN_POWER = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "input_power")
                )
            except ValueError and TypeError:
                IN_POWER = 0
            try:
                OUT_POWER = float(
                    self.sonic_db.get(self.sonic_db.STATE_DB, key, "output_power")
                )
            except ValueError and TypeError:
                OUT_POWER = 0
            # print(psu_name, IN_POWER, OUT_POWER)
            self.metric_psu.labels(psu_name, "input").set(IN_POWER)
            self.metric_psu.labels(psu_name, "output").set(OUT_POWER)

    def export_sys_info(self):
        PART_NUMBER = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x22", "Value")
        )
        SERIAL_NUMBER = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x23", "Value")
        )
        MAC_ADDR = _decode(
            self.sonic_db.get(self.sonic_db.STATE_DB, "EEPROM_INFO|0x24", "Value")
        )
        self.sys_info.info(
            {
                "part_name": PART_NUMBER,
                "serial_name": SERIAL_NUMBER,
                "mac_address": MAC_ADDR,
            }
        )
        # print(PART_NUMBER, SERIAL_NUMBER, MAC_ADDR)

    def export_bgp_peer_status(self):
        # vtysh -c "show ip bgp neighbors Ethernet32 json"
        # get - bgpState and bgpTimerUp (available only when interface is up)
        try:
            keys = self.sonic_db.keys(self.sonic_db.CONFIG_DB, pattern="BGP_NEIGHBOR*")
            for key in keys:
                key = _decode(key)
                bgp_neighbour = key.split("|")[-1]  # eg Ethernet32
                command = 'vtysh -c "show ip bgp neighbors {} json"'.format(
                    bgp_neighbour
                )
                # print(subprocess.getoutput(command))
                cmd_out = json.loads(subprocess.getoutput(command))
                bgpState = cmd_out[bgp_neighbour]["bgpState"]
                # states as one of these - "idle","connect","active","opensent","openconfirm","Established"
                try:
                    _ = int(cmd_out[bgp_neighbour]["bgpTimerUp"])
                    self.metric_bgp_peer_status.labels(bgp_neighbour, bgpState).state(
                        "up"
                    )
                except KeyError:
                    self.metric_bgp_peer_status.labels(bgp_neighbour, bgpState).state(
                        "down"
                    )
        except Exception as e:
            print("export_bgp_peer_status : Exception : ", e)

    def export_bgp_num_routes(self):
        # vtysh -c "show ip bgp neighbors Ethernet32 prefix-counts  json"
        # get - pfxCounter
        try:
            keys = self.sonic_db.keys(self.sonic_db.CONFIG_DB, pattern="BGP_NEIGHBOR*")
            for key in keys:
                key = _decode(key)
                bgp_neighbour = key.split("|")[-1]  # eg Ethernet32
                command = (
                    'vtysh -c "show ip bgp neighbors {} prefix-counts json"'.format(
                        bgp_neighbour
                    )
                )
                # print(subprocess.getoutput(command))
                cmd_out = json.loads(subprocess.getoutput(command))
                bgp_count = cmd_out["pfxCounter"]
                self.metric_bgp_num_routes.labels(bgp_neighbour).set(bgp_count)
        except Exception as e:
            print("export_bgp_num_routes : Exception :", e)

    def export_system_top10_process(self):
        # read "/usr/local/include/top_process.json" file and get the top process
        try:
            with open("/usr/local/include/top_process.json", "r") as f:
                top_process = json.loads(f.read())
                for cpu_process in top_process["top10_cpu_process"]:
                    self.metric_system_top10_cpu_percent.labels(
                        cpu_process["pid"], cpu_process["cmd"]
                    ).set(cpu_process["cpu_per"])

                for mem_process in top_process["top10_mem_process"]:
                    self.metric_system_top10_mem_percent.labels(
                        mem_process["pid"], mem_process["cmd"]
                    ).set(mem_process["mem_per"])
        except Exception as e:
            print("export_system_top10_process : Exception = ", e)

    def start_export(self):
        try:
            self.export_intf_counter()
            self.export_intf_queue_counters()
            self.export_intf_cable_data()
            self.export_intf_sensor_data()
            self.export_sys_info()
            self.export_psu_info()
            self.export_bgp_peer_status()
            self.export_bgp_num_routes()
            self.export_system_top10_process()
        except Exception as e:
            print("Exception: ", e)


def main():
    data_extract_interval = 10
    port = 9101

    exp = Export()
    prom.start_http_server(port)
    while True:
        exp.start_export()
        time.sleep(data_extract_interval)


if __name__ == "__main__":
    file_path = os.path.dirname(__file__)
    if file_path != "":
        # to make sure the json file gets created in same path as this script
        os.chdir(file_path)
    main()
