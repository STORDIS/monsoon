#!/usr/bin/env bash
PLATFORM=$(show platform summary | grep "Platform: " | xargs -n 1 | tail -1)
redis-dump -d 0 > ${PLATFORM}.appl.json
redis-dump -d 1 > ${PLATFORM}.asic.json
redis-dump -d 2 > ${PLATFORM}.counters.json
redis-dump -d 3 > ${PLATFORM}.loglevel.json
redis-dump -d 4 > ${PLATFORM}.config.json
redis-dump -d 5 > ${PLATFORM}.pfc_wd.json
redis-dump -d 6 > ${PLATFORM}.state.json
redis-dump -d 7 > ${PLATFORM}.snmp_overlay.json
redis-dump -d 8 > ${PLATFORM}.error.json