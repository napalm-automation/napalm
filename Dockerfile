FROM debian:stretch

## Install min deps
RUN apt-get update

## Install NAPALM & underlying libraries dependencies
RUN apt-get install -y python-cffi python-dev libxslt1-dev libssl-dev libffi-dev \
    && apt-get install -y python-pip \
    && pip install -U cffi \
    && pip install -U cryptography \
    && pip install napalm

RUN rm -rf /var/lib/apt/lists/*
