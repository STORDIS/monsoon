FROM python:3.9-slim-bullseye

COPY src/sonic_exporter/exporter.py /usr/local/bin/exporter.py
COPY src/sonic_exporter/requirements.txt /home/requirements.txt
RUN pip3 install -r /home/requirements.txt && mkdir -p /src && chmod +x /usr/local/bin/exporter.py
COPY src/sonic-py-swsssdk /src
RUN pip3 install /src && rm -rf /src

CMD /usr/local/bin/exporter.py
