# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

############################################################
# Dockerfile to build Traffic Ops container images
# Based on CentOS 7.2
############################################################


FROM centos:8

EXPOSE 443
ENV MOJO_MODE=production\
    POSTGRES_HOME=/usr/pgsql-9.6\
    PERL5LIB=/opt/traffic_ops/app/local/lib/perl5

RUN set -o errexit -o pipefail;\
    dnf -y update;\
    dnf -y module disable postgresql;\
    dnf -y install dnf-plugins-core epel-release patch;\
    dnf -y config-manager --set-enabled PowerTools;\
    dnf -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm;\
    dnf -y install \
        bind-utils \
        cpanminus \
        expat-devel \
        gcc-c++ \
        gettext \
        git \
        golang \
        iproute \
        jq \
        libcurl-devel \
        libidn-devel \
        libpcap-devel \
        mkisofs \
        net-tools \
        nmap-ncat \
        openssl \
        openssl-devel \
        perl \
        perl-core \
        perl-Crypt-ScryptKDF \
        perl-DBD-Pg \
        perl-DBI \
        perl-DBIx-Connector \
        perl-Digest-SHA1 \
        perl-JSON \
        perl-JSON-PP \
        perl-libwww-perl \
        perl-TermReadKey \
        perl-Test-CPAN-Meta \
        perl-WWW-Curl \
        postgresql96-devel \
        rsync \
        tar &&\
    dnf -y clean all && mkdir -p /opt/traffic_ops/app/public

ADD traffic_router/core/src/test/resources/geo/GeoLite2-City.mmdb.gz /opt/traffic_ops/app/public/

WORKDIR /opt/traffic_ops/app
ADD traffic_ops/app/cpanfile traffic_ops/install/bin/install_goose.sh ./

# These cpan modules fail out of the box but can be patched to succeed
RUN set -o errexit -o nounset;\
    cpanm -i inc::Module::Install;\
    modules=(WWW::Curl::Easy Net::Pcap);\
    patches=(\
        http://cpan.cpantesters.org/authors/id/S/SR/SREZIC/patches/WWW-Curl-4.17-RT117793.patch \
        https://src.fedoraproject.org/rpms/perl-Net-Pcap/raw/master/f/Net-Pcap-0.18-Fix-build-with-libpcap-1.9.0.patch \
    );\
    for index in ${!modules[@]}; do \
        set -o errexit -o nounset;\
        SHELL=/bin/bash cpanm --local-lib=./local --look ${modules[$index]} <<<"\
            trap 'echo Error on line \${LINENO} of cpanm look for ${modules[$index]}; exit 1' ERR;\
            set -o errexit -o pipefail;\
            curl -v ${patches[$index]} |\
                patch;\
            perl Makefile.PL;\
            make;\
            make install;\
        ";\
        # Make sure the module is installed because cpan --look always returns exit code 0
        perl -M${modules[$index]} -e '';\
    done;

RUN cpanm -l ./local Carton && \
    ./local/bin/carton && \
    rm -rf $HOME/.cpan* /tmp/Dockerfile /tmp/local.tar.gz ./cpanfile
RUN ./install_goose.sh

# Override TRAFFIC_OPS_RPM arg to use a different one using --build-arg TRAFFIC_OPS_RPM=...  Can be local file or http://...
ARG TRAFFIC_OPS_RPM=infrastructure/cdn-in-a-box/traffic_ops/traffic_ops.rpm
ADD $TRAFFIC_OPS_RPM /
RUN dnf install -y /$(basename $TRAFFIC_OPS_RPM) && \
    rm /$(basename $TRAFFIC_OPS_RPM) && \
    dnf -y clean all && \
    rm /opt/traffic_ops/app/bin/traffic_ops_golang

# Run carton again, in case the cpanfile included in the RPM differs from the one used earlier in the
# build (should never happen - Perl is supposed to be going away)
RUN ./local/bin/carton && \
    rm -rf $HOME/.cpan* /tmp/Dockerfile /tmp/local.tar.gz

ADD infrastructure/cdn-in-a-box/enroller/server_template.json \
    infrastructure/cdn-in-a-box/traffic_ops/run.sh \
    infrastructure/cdn-in-a-box/traffic_ops/config.sh \
    infrastructure/cdn-in-a-box/traffic_ops/adduser.pl \
    infrastructure/cdn-in-a-box/traffic_ops/to-access.sh \
    infrastructure/cdn-in-a-box/traffic_ops/generate-certs.sh \
    infrastructure/cdn-in-a-box/traffic_ops/trafficops-init.sh \
    infrastructure/cdn-in-a-box/variables.env \
    /

ADD infrastructure/cdn-in-a-box/traffic_ops_data /traffic_ops_data

CMD /run.sh
