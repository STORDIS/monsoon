#!/bin/bash
DOCKER_BUILDKIT=1 docker build -t palcnetworks/sonic_monitoring:latest  .
docker push palcnetworks/sonic_monitoring:latest
