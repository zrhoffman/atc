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
# Dockerfile to build Traffic Server container images
#   as Edges for Traffic Control 1.4
# Based on CentOS 6.6
############################################################

FROM centos:7
MAINTAINER dev@trafficcontrol.apache.org

# Switch to a vault now that CentOS7 reached EoL and dropped mirrors
# https://unix.stackexchange.com/questions/398609/how-do-i-stick-with-one-version-on-centos-7-via-yum-update/444344#444344
RUN sed -e '/mirrorlist=.*/d' \
    -e 's/#baseurl=/baseurl=/' \
    -e "s/mirror.centos.org\\/centos/vault.centos.org/g" \
    -e "s/\$releasever/7.9.2009/g" \
    -i /etc/yum.repos.d/CentOS-Base.repo

RUN yum install -y httpd createrepo yum-utils

RUN mkdir -p /var/www/html/traffic-control/7/x86_64/Packages
RUN sed -i -e 's/#ServerName www.example.com:80/ServerName www.example.com:80/g' /etc/httpd/conf/httpd.conf

EXPOSE 80
ADD yumserver/run.sh /
ENTRYPOINT /run.sh
