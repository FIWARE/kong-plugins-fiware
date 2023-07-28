ARG BASE=ubuntu:20.04
FROM ${BASE}

ARG PONGO_VERSION=1.3.0

USER root

RUN apt update \
    && apt install -y git curl docker-compose \
    && git clone https://github.com/kong/kong-pongo.git /kong-pongo \
    && cd /kong-pongo \
    && git checkout $PONGO_VERSION

WORKDIR /pongo_wd
ENTRYPOINT ["/kong-pongo/pongo.sh"]