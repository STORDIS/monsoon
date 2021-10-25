#!/bin/bash
make
DOCKER_BUILDKIT=1 docker build -t stordis/sonic-monitoring:latest  .
docker push stordis/sonic-monitoring:latest
