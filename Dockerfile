# syntax=docker/dockerfile:1.4

FROM scratch AS installer
COPY ./ /var/cache/napalm/

FROM python:3.9-slim

RUN --mount=type=bind,from=installer,source=/var/cache/napalm,target=/var/cache/napalm,rw \
    apt-get update && \
    apt-get install -y \
        python3.9-dev libxslt1-dev libssl-dev libffi-dev && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/* && \
    pip --no-cache-dir install -U cffi cryptography /var/cache/napalm/

 ENTRYPOINT ["napalm"]
