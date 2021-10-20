#!/bin/bash

#Copy python script to monitor host services
cp top_process.py /usr/local/include/top_processes.py
cp top_process.json usr/local/include/top_process.json

#Copy Systemd service file
cp top_processes.service /etc/systemd/system/top_processes.service

systemctl daemon-reload


