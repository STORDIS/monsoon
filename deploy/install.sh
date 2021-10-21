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

#install docker-compose if it doesnt exist
file='/usr/local/bin/docker-compose'
if [ -f $file ];
then
	echo "$file exists."
else
	echo "$file does NOT exists... Installing "
	sudo curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
	sudo chmod +x /usr/local/bin/docker-compose
fi

#Start docker-compose file
REDIS_AUTH=$(cat /run/redis/auth/passwd) docker-compose up -d
