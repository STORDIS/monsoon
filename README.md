# Monsoon - main repository

1. SONIC exporter

```console
$ docker run --name sonic_monitoring --network=host --pid=host --privileged --restart=always -d -e REDIS_AUTH=$(cat /run/redis/auth/passwd) -v /var/run/redis:/var/run/redis -v /usr/bin/vtysh:/usr/bin/vtysh -v /usr/bin/docker:/usr/bin/docker -v /var/run/docker.sock:/var/run/docker.sock  registry.devops.telekom.de/schiff/sonic-monitoring:latest
```

2. Node Exporter
```console
$ docker run --name node-exporter --network=host --pid=host --privileged --restart=always -d -v /proc:/host/proc:ro -v /sys:/host/sys:ro -v /:/rootfs:ro docker.io/prom/node-exporter:v1.3.0
```

3. Nginx
```bash
#! /usr/bin/env bash
mkdir -p ${HOME}/nginx/ssl
cp ${HOME}/default.conf.template ${HOME}/nginx/default.conf.template
export CERT_CONFIG=$(mktemp)
openssl dhparam -dsaparam -out dhparam.pem 4096
cat cert.config.template | HOSTNAME=$(hostname --fqdn) envsubst > /tmp/cert.config
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out ${HOME}/nginx/ssl/server_$(hostname --fqdn).crt -keyout ${HOME}/nginx/ssl/server_$(hostname --fqdn).key -config /tmp/cert.config
```
```console
$ docker run --name nginx-proxy --network=host --pid=host --privileged --restart=always -d -e DOLLAR_SIGN='$' -e NGINX_HOST=$(hostname --fqdn) NGINX_PORT=5556 -v ${HOME}/nginx/ssl:/etc/nginx/ssl/:ro -v ${HOME}/nginx/default.conf.template:/etc/nginx/templates/default.conf.template:ro docker.io/library/nginx:1.21
```

## Central Client Certificate Generation
```bash
#! /usr/bin/env bash
export CERT_CONFIG=$(mktemp)
cat cert.config.template | HOSTNAME=$(hostname --fqdn) envsubst > ${CERT_CONFIG}
openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out client.crt -keyout client.key -config ${CERT_CONFIG}
```

## Details:

1. src/ folder has below subfolders
- sonic_exporter - this folder contains - exporter script
- sonic-py-swsssdk - this is a git submodule pulled from [github](https://github.com/Azure/sonic-py-swsssdk) as a redis connector used by python_exporter.

2. Dockerfile - This file can be used to build docker image.


## Environment Variables

| VARIABLE                  | Description                                                           | Default           |
| ------------------------- | --------------------------------------------------------------------- | ----------------- |
| DEVELOPER_MODE            | This enables the Mock functionality of the exporter for local testing | `False`           |
| REDIS_COLLECTION_INTERVAL | The interval in which the redis-client fetches data from the switch   | `30` (in seconds) |
| REDIS_AUTH                | The secret to login to the redis db                                   | `RAISE`           |
| SONIC_EXPORTER_PORT       | The port on which the exporter listens                                | `9101`            |
| SONIC_EXPORTER_ADDRESS    | The address on which the exporter listens                             | `localhost`       |
| SONIC_EXPORTER_LOGLEVEL   | The loglevel for the exporter                                         | `INFO`            |

## Building

```console
$ export VERSION="latest"
$ podman build -t sonic_monitoring:${VERSION} .
[1/2] STEP 1/7: FROM python:3.10-bullseye
Resolving "python" using unqualified-search registries (/etc/containers/registries.conf)
Trying to pull docker.io/library/python:3.10-bullseye...
Getting image source signatures
Copying blob 461bb1d8c517 done  
Copying blob 724cfd2dc19b done  
Copying blob e6d3e61f7a50 done  
Copying blob 412caad352a3 done  
Copying blob 808edda3c2e8 done  
Copying blob 0c6b8ff8c37e done  
Copying blob 8bd4965a24ab done  
Copying blob fccd5fa208a8 done  
Copying blob af1ca64a0eec done  
Copying config e2e732b795 done  
Writing manifest to image destination
Storing signatures
[1/2] STEP 2/7: COPY . .
--> b1bb5809caf
[1/2] STEP 3/7: RUN pip3 install poetry
--> 1f58ca76511
[1/2] STEP 4/7: RUN poetry export -f requirements.txt -o /home/requirements.txt
--> aafc87b688d
[1/2] STEP 5/7: RUN cd src/sonic-py-swsssdk && python setup.py build sdist && cd ../..
--> b056c2dad7e
[1/2] STEP 6/7: RUN poetry build
--> 7a0b271d272
[1/2] STEP 7/7: RUN cp dist/sonic_exporter*.tar.gz /home/ && cp src/sonic-py-swsssdk/dist/swsssdk-*.tar.gz /home
--> c1af04863c0
[2/2] STEP 1/5: FROM python:3.10-slim-bullseye
[2/2] STEP 2/5: COPY --from=0 /home/requirements.txt /home/requirements.txt
--> 9d98422dfc2
[2/2] STEP 3/5: COPY --from=0 /home/*.tar.gz /home/
--> bfdf47151b8
[2/2] STEP 4/5: RUN pip3 install --pre -r /home/requirements.txt && pip3 install /home/*.tar.gz && mkdir -p /src
--> a9de129245a
[2/2] STEP 5/5: CMD sonic_exporter
[2/2] COMMIT sonic_monitoring:${VERSION}
--> f71e7b8de82
Successfully tagged localhost/sonic_monitoring:${VERSION}
f71e7b8de82e5eabfe66c803538f19d1fb3c44b3b0edf9725e9eb61943d4a093
$ podman save --format docker-archive localhost/sonic_monitoring:${VERSION} | gzip  > sonic-monitoring_${VERSION}.tar.gz
$ ls
sonic-monitoring_${VERSION}.tar.gz
```

## Loading the image on a switch

```console
$ docker load -i sonic-monitoring_${VERSION}.tar.gz
e1bbcf243d0e: Loading layer  83.88MB/83.88MB
7944c75516ae: Loading layer  3.401MB/3.401MB
775d27396430: Loading layer  30.41MB/30.41MB
70c19fb3395a: Loading layer  4.608kB/4.608kB
834714e112d6: Loading layer  10.09MB/10.09MB
6062c6897570: Loading layer  3.584kB/3.584kB
c7e4a0cae15f: Loading layer  36.35kB/36.35kB
2d345aa4239f: Loading layer   10.3MB/10.3MB
Loaded image: localhost/sonic_monitoring:${VERSION}
```
