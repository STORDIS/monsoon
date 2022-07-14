FROM ubuntu:20.04

RUN apt-get update  && apt-get install -y python3 python3-pip supervisor

#COPY binary
COPY src/node_exporter/node_exporter /usr/bin/
COPY src/sonic_exporter/exporter.py /usr/bin/exporter.py
COPY src/sonic_exporter/requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt
RUN --mount=type=bind,source=src/sonic-py-swsssdk,target=/src,rw pip3 install /src
#Copy supervisor conf file for node exporter and update
COPY src/node_exporter/node_exporter.conf /etc/supervisor/conf.d/
COPY src/sonic_exporter/sonic_exporter.conf /etc/supervisor/conf.d/

RUN mkdir -p /host/proc /host/sys /rootfs

CMD (supervisord -n)
