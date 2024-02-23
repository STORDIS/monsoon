FROM python:3.12-bullseye AS builder

COPY . .
RUN pip3 install poetry
RUN poetry export -f requirements.txt -o /home/requirements.txt
RUN cd src/sonic-py-swsssdk && python setup.py build sdist && cd ../..
RUN poetry build
RUN cp dist/sonic_exporter*.tar.gz /home/ && cp src/sonic-py-swsssdk/dist/swsssdk-*.tar.gz /home

FROM python:3.12-slim-bullseye

COPY --from=builder /home/requirements.txt /home/requirements.txt
COPY --from=builder /home/*.tar.gz /home/
RUN apt-get update && apt-get install -y \
    nano \
    libopts25 \
    libedit2 \
    libcgroup1 \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --pre -r /home/requirements.txt && pip3 install /home/*.tar.gz && mkdir -p /src && rm /home/*

CMD sonic_exporter
