# Monsoon - main repository

This repository contains 

1. SONIC exporter

    * `$ docker run --name sonic_monitoring --network=host --pid=host --privileged --restart=always -d  -e REDIS_COLLECTION_INTERVAL=30 -e REDIS_AUTH=$(cat /run/redis/auth/passwd) -v /var/run/redis:/var/run/redis -v /usr/bin/vtysh:/usr/bin/vtysh -v /usr/bin/docker:/usr/bin/docker -v /var/run/docker.sock:/var/run/docker.sock  stordis/sonic_monitoring:0.1.0`
2. Node Exporter
    * `$ docker run --name node-exporter --network=host --pid=host --privileged --restart=always -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /:/rootfs:ro prom/node-exporter:v1.3.0`


# Details:

1. src/ folder has below subfolders
- python_exporter - this folder contains - exporter script, requirements.txt and supervisor conf file `python_exporter.conf`
- sonic-py-swsssdk - this is a git submodule pulled from [github](https://github.com/Azure/sonic-py-swsssdk) as a redis connector used by python_exporter.

2. Dockerfile - This file can be used to build docker image.

4. makeDockerAndPush.sh -  Build docker image and push to docker hub.

5. deploy/ folder has below contents:
> **This folder can be zipped and exported to any Broadcom SONiC platform**  

> ***Run `install.sh` script to bring up monitoring docker container**

> ***Run `uninstall.sh` script to revert the changes made by install script**
- docker-compose.yml - file to bring up the docker image on SONiC board.
- top_process.py - file which reads top 10 CPU and Memory processes and export to a JSON file.
- top_process.json - placeholder output file of above script.
- top_processes.service - systemd service file for top_processes
- install.sh  - script to be run on SONiC board for installation (to bring up monitoring docker container, copying systemd service files and other supporting files).
- uninstall.sh  - script to be run on SONiC board for uninstallation (to revert all changes done by install script).
