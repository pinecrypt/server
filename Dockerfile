FROM ubuntu:20.04 as base
ENV container docker
ENV PYTHONUNBUFFERED=1
ENV LC_ALL C.UTF-8
ENV DEBIAN_FRONTEND noninteractive
RUN echo force-unsafe-io > /etc/dpkg/dpkg.cfg.d/docker-apt-speedup \
 && echo "Dpkg::Use-Pty=0;" > /etc/apt/apt.conf.d/99quieter \
 && apt-get update -qq \
 && apt-get install -y -qq \
    bash build-essential python3-dev cython3 libffi-dev libssl-dev \
    libkrb5-dev ldap-utils libsasl2-modules-gssapi-mit libsasl2-dev libldap2-dev \
    python python3-pip python3-cffi iptables ipset \
    strongswan libstrongswan-extra-plugins libcharon-extra-plugins \
    openvpn  libncurses5-dev gawk wget unzip git rsync \
 && apt-get clean \
 && rm /etc/dpkg/dpkg.cfg.d/docker-apt-speedup

WORKDIR /src
COPY requirements.txt /src/
RUN pip3 install --no-cache-dir -r requirements.txt
COPY config/strongswan.conf /etc/strongswan.conf
COPY pinecrypt/. /src/pinecrypt/
COPY helpers /helpers/
COPY MANIFEST.in setup.py README.md /src/
COPY misc/. /src/misc/
RUN python3 -m compileall .
RUN pip3 install --no-cache-dir .
RUN rm -Rfv /src
