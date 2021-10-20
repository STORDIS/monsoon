FROM ubuntu:20.04

RUN apt-get update  && apt-get install -y python3 python3-pip supervisor

#COPY binary
COPY src/node_exporter/node_exporter /usr/bin/
COPY src/python_exporter/exporter.py /usr/bin/exporter.py
COPY src/python_exporter/requirements.txt /home/requirements.txt
RUN pip3 install -r /home/requirements.txt

#Copy supervisor conf file for node exporter and update
COPY src/node_exporter/node_exporter.conf /etc/supervisor/conf.d/
#RUN supervisorctl reread && supervisorctl update

RUN mkdir -p /host/proc /host/sys /rootfs

CMD (supervisord -n)
