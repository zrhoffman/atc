#!/usr/bin/env bash

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

trap 'echo "Error on line ${LINENO} of ${0}" >/proc/1/fd/2; exit 1' ERR
set -o errexit -o nounset


docker_stdout=/proc/1/fd/1

source /etc/profile.d/cache_debugging_port.sh # Sets CACHE_DEBUGGING_PORT when invoked from cron

dlv \
		--log-dest=$docker_stdout \
		--listen=:"$CACHE_DEBUGGING_PORT" \
		--accept-multiclient=true \
		--headless=true \
		--api-version=2 exec \
		"$(dirname "$0")/atstccfg-binary" -- "$@" &

{
until pgrep atstccfg-binary >/dev/null; do
	echo 'Waiting for atstccfg to start...'
	sleep .5
done
while pgrep atstccfg-binary >/dev/null; do
	echo 'Waiting for atstccfg to exit...'
	sleep 1
done
echo 'It totally exited'
} >$docker_stdout
kill %
