#!/usr/bin/env bash
PLATFORM=$(show platform summary | grep "Platform: " | xargs -n 1 | tail -1)
# These two databases are separate instances each
redis-dump -d 0 -p 63792 | python -m json.tool > ${PLATFORM}.appl.json
redis-dump -d 1 -p 63793 | python -m json.tool > ${PLATFORM}.asic.json
# Everything else lives here.
redis-dump -d 2 | python -m json.tool > ${PLATFORM}.counters.json
redis-dump -d 3 | python -m json.tool > ${PLATFORM}.loglevel.json
redis-dump -d 4 | python -m json.tool > ${PLATFORM}.config.json
redis-dump -d 5 | python -m json.tool > ${PLATFORM}.pfc_wd.json
redis-dump -d 6 | python -m json.tool > ${PLATFORM}.state.json
redis-dump -d 7 | python -m json.tool > ${PLATFORM}.snmp_overlay.json
redis-dump -d 8 | python -m json.tool > ${PLATFORM}.error.json
vtysh -c "show bgp vrf all summary json" | python -m json.tool > ${PLATFORM}.frr.show_bgp_vrf_all_summary.json
vtysh -c "show evpn vni detail json" | python -m json.tool > ${PLATFORM}.frr.show_evpn_vni_detail.json
