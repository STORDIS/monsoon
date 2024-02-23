#!/usr/bin/env bash
declare -r PLATFORM=$(show platform summary | grep "Platform: " | xargs -n 1 | tail -1)
declare -r VERSION=$(show version | grep "SONiC Software Version:" | xargs -n 1 | tail -1)

# These two databases are separate instances each
while IFS=" " read -r id name instance port socket ; do
    internal_name=$( echo "${name%_DB}" | tr '[:upper:]' '[:lower:]')
    if [[ $VERSION == "SONiC-OS-4.0.2-Enterprise_Base" ]]
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
vtysh -c "show ip route vrf all summary json" | python -m json.tool > ${PLATFORM}.frr.show_ip_route_vrf_all_summary.json
vtysh -c "show ipv6 route vrf all summary json" | python -m json.tool > ${PLATFORM}.frr.show_ipv6_route_vrf_all_summary.json
# Let the for loop run on different file descriptor as it seems vtysh uses stdin as well.
while IFS="," read -r vrf neighbor <&3; do
    echo "Dumping VRF[${vrf}]::${neighbor} Summary"
    vtysh -c "show bgp vrf ${vrf} summary json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_summary.json
    echo "Dumping VRF[${vrf}]::${neighbor} ipv4 unicast"
    vtysh -c "show bgp vrf ${vrf} ipv4 unicast summary json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv4_unicast_summary.json
    vtysh -c "show bgp vrf ${vrf} ipv4 unicast neighbors ${neighbor} advertised-routes json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv4_unicast_neighbors_${neighbor}_advertised-routes.json
    vtysh -c "show bgp vrf ${vrf} ipv4 unicast neighbors ${neighbor} flap-statistics json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv4_unicast_neighbors_${neighbor}_flap-statistics.json
    vtysh -c "show bgp vrf ${vrf} ipv4 unicast neighbors ${neighbor} received-routes json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv4_unicast_neighbors_${neighbor}_received-routes.json
    vtysh -c "show bgp vrf ${vrf} ipv4 unicast neighbors ${neighbor} prefix-counts json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv4_unicast_neighbors_${neighbor}_prefix-counts.json
    echo "Dumping VRF[${vrf}]::${neighbor} ipv6 unicast"
    vtysh -c "show bgp vrf ${vrf} ipv6 unicast summary json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv6_unicast_summary.json
    vtysh -c "show bgp vrf ${vrf} ipv6 unicast neighbors ${neighbor} advertised-routes json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv6_unicast_neighbors_${neighbor}_advertised-routes.json
    vtysh -c "show bgp vrf ${vrf} ipv6 unicast neighbors ${neighbor} flap-statistics json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv6_unicast_neighbors_${neighbor}_flap-statistics.json
    vtysh -c "show bgp vrf ${vrf} ipv6 unicast neighbors ${neighbor} received-routes json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv6_unicast_neighbors_${neighbor}_received-routes.json
    vtysh -c "show bgp vrf ${vrf} ipv6 unicast neighbors ${neighbor} prefix-counts json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_ipv6_unicast_neighbors_${neighbor}_prefix-counts.json
    echo "Dumping VRF[${vrf}]::${neighbor} l2vpn evpn"
    vtysh -c "show bgp vrf ${vrf} l2vpn evpn summary json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_l2vpn_evpn_summary.json
    vtysh -c "show bgp vrf ${vrf} l2vpn evpn statistics json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_${vrf}_l2vpn_evpn_statistics.json
done 3< <(jq -r 'keys[] as $k | "\($k),\(.[$k] | .[].peers | keys[])"' ${PLATFORM}.frr.show_bgp_vrf_all_summary.json | uniq)
