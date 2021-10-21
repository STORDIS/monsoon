# sonic_monitoring

This repository contains 
1. Node exporter 
2. Python exporter

# Files and Folder Structure:

1. src/ folder has below subfolders
- node_exporter - cloned from [github](https://github.com/prometheus/node_exporter) , contains supervisor conf file `node_exporter.conf`
- python_exporter - exporter code which fetches data from REDIS and export using promethues client.
- sonic-py-swsssdk - this is a git submodule pulled from [github](https://github.com/Azure/sonic-py-swsssdk) as a redis connector used by python_exporter.

2. Dockerfile - This file can be used to build docker image.

3. Makefile -  File to compile source code.

4. makeDockerAndPush.sh -  Build docker image and push to docker hub.

5. deploy/ folder has below contents:
- docker-compose.yml - file to bring up the docker image on SONiC board.
- top_process.py - file which reads top 10 CPU and Memory processes and export to a JSON file.
- top_process.json - output file of above script.
- top_processes.service - systemd service file for top_processes
- install.sh  - script to be run on SONiC board for installation of docker and systemd service.

# Development

1. git clone https://gitlab.stordis.com/cshivash/sonic_monitoring.git
2. cd sonic_monitoring
3. git submodule update 
4. For compiling execute command: 
    `make`
5. For building docker image execute script:
    `./makeDockerAndPush.sh`
