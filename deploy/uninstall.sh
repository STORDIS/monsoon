#!/bin/bash

#set -x

echo "Stopping sonic_monitor container and removing docker image"
sudo docker-compose down
sudo docker rmi stordis/monsoon

echo "stop and disable top_process systemd service"
sudo systemctl stop top_processes
sudo systemctl disable top_processes 
#remove Systemd service file
sudo rm /etc/systemd/system/top_processes.service
sudo systemctl daemon-reload

echo "remove copied python scripts"
sudo rm /usr/local/include/top_processes.py
sudo rm /usr/local/include/top_process.json

echo "uninstall complete"