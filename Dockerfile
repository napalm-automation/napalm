FROM debian:stretch

## Install min deps
RUN apt-get update

COPY ./ /var/cache/napalm/

## Install NAPALM & underlying libraries dependencies
RUN apt-get install -y python-cffi python-dev libxslt1-dev libssl-dev libffi-dev \
    && apt-get install -y python-pip \
    && pip install -U cffi \
    && pip install -U cryptography \
    && pip install /var/cache/napalm/

RUN rm -rf /var/lib/apt/lists/*
