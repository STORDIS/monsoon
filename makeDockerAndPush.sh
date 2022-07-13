#!/bin/bash
DOCKER_BUILDKIT=1 docker build -t stordis/monsoon:latest  .
docker push stordis/monsoon:latest
