#!/usr/bin/env bash
declare -r PLATFORM=$(show platform summary | grep "Platform: " | xargs -n 1 | tail -1)
declare -r VERSION=$(show version | grep "SONiC Software Version:" | xargs -n 1 | tail -1)
# These two databases are separate instances each

while IFS=" " read -r id name instance port socket ; do
    internal_name=$( echo "${name%_DB}" | tr '[:upper:]' '[:lower:]')
    if [[ $VERSION == "SONiC-OS-4.0.1-Enterprise_Base" ]]
        then
            # $ show database  map --verbose
            #   ID                Name    Instance    TCP Port            Unix Socket Path
            # ----  ------------------  ----------  ----------  --------------------------
            #    0             APPL_DB      redis2       63792  /var/run/redis/redis2.sock
            #    1             ASIC_DB      redis3       63793  /var/run/redis/redis3.sock
            #    2         COUNTERS_DB      redis6       63796  /var/run/redis/redis6.sock
            #    3         LOGLEVEL_DB       redis        6379   /var/run/redis/redis.sock
            #    4           CONFIG_DB       redis        6379   /var/run/redis/redis.sock
            #    5     FLEX_COUNTER_DB       redis        6379   /var/run/redis/redis.sock
            #    6            STATE_DB       redis        6379   /var/run/redis/redis.sock
            #    7     SNMP_OVERLAY_DB       redis        6379   /var/run/redis/redis.sock
            #    8            ERROR_DB       redis        6379   /var/run/redis/redis.sock
            #    9          RESTAPI_DB       redis        6379   /var/run/redis/redis.sock
            #   10          GB_ASIC_DB       redis        6379   /var/run/redis/redis.sock
            #   11      GB_COUNTERS_DB       redis        6379   /var/run/redis/redis.sock
            #   12  GB_FLEX_COUNTER_DB       redis        6379   /var/run/redis/redis.sock
            #   15            EVENT_DB      redis4       63794  /var/run/redis/redis4.sock
            redis-dump -w $(cat /var/run/redis/auth/passwd) -d $id -p $port | python -m json.tool > ${PLATFORM}.${internal_name}.json
    fi
    if [[ $VERSION == "SONiC-OS-3.5.0-Enterprise_Base" ]]
        then
            # $ show database map
            #   ID             Name    Instance    TCP Port            Unix Socket Path
            # ----  ---------------  ----------  ----------  --------------------------
            #    0          APPL_DB      redis2       63792  /var/run/redis/redis2.sock
            #    1          ASIC_DB      redis3       63793  /var/run/redis/redis3.sock
            #    2      COUNTERS_DB       redis        6379   /var/run/redis/redis.sock
            #    3      LOGLEVEL_DB       redis        6379   /var/run/redis/redis.sock
            #    4        CONFIG_DB       redis        6379   /var/run/redis/redis.sock
            #    5        PFC_WD_DB       redis        6379   /var/run/redis/redis.sock
            #    6         STATE_DB       redis        6379   /var/run/redis/redis.sock
            #    7  SNMP_OVERLAY_DB       redis        6379   /var/run/redis/redis.sock
            #    8         ERROR_DB       redis        6379   /var/run/redis/redis.sock
            redis-dump -d $id -p $port | python -m json.tool > ${PLATFORM}.${internal_name}.json
    fi
done < <(show database map | grep /var/run)
# Everything else lives here.
vtysh -c "show bgp vrf all summary json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_all_summary.json
vtysh -c "show evpn vni detail json" | python -m json.tool > ${PLATFORM}.frr.show_evpn_vni_detail.json
