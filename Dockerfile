FROM python:3.6-slim-stretch

COPY ./ /var/cache/napalm/

RUN apt-get update \
 && apt-get install -y python-dev python-cffi libxslt1-dev libssl-dev libffi-dev \
 && apt-get autoremove \
 && rm -rf /var/lib/apt/lists/* \
 && pip --no-cache-dir install -U cffi cryptography /var/cache/napalm/ \
 && rm -rf /var/cache/napalm/
