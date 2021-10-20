#!/bin/bash

#set -x

#Copy python script to monitor host services
sudo cp top_process.py /usr/local/include/top_processes.py
sudo cp top_process.json /usr/local/include/top_process.json

#Copy Systemd service file
sudo cp top_processes.service /etc/systemd/system/top_processes.service

#Restart systemd service
sudo systemctl daemon-reload
sudo systemctl stop top_processes
sudo systemctl start top_processes

#Start docker-compose file
docker-compose up -d
