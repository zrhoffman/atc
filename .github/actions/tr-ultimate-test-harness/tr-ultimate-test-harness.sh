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

trap 'echo "Error on line ${LINENO} of ${0}"; exit 1' ERR;
set -o xtrace
set -o errexit -o nounset -o pipefail

# Get atc-ready function
source dev/atc.dev.sh
export -f atc-ready

# Snapshot
cdn_id="$(<<<"$server" jq .cdnId)"
to-put "api/$TO_API_VERSION/snapshot?cdnID=${cdn_id}"

echo "Waiting for Traffic Monitor to serve a snapshot..."
if ! timeout 10m curl \
	--retry 99999 \
	--retry-delay 5 \
	--show-error \
	-fIso/dev/null \
	http://localhost/publish/CrConfig; then
	echo "CrConfig was not available from Traffic Monitor within 10 minutes!"
	trap - ERR
	echo 'Exiting...'
	exit 1
fi


deliveryservice=cdn.dev-ds.ciab.test
echo "Waiting for Delivery Service ${deliveryservice} to be available..."
if ! timeout 10m bash -c 'atc-ready -d'; then
	echo "Delivery Service ${deliveryservice} was not available within 10 minutes!"
	trap - ERR
	echo 'Exiting...'
	exit 1
fi

http_result=0 dns_result=0

http_requests_threshold=1200
dns_requests_threshold=2500
# Compile the tests
go test -c ./traffic_router/ultimate-test-harness
if ! ./ultimate-test-harness.test -test.v -test.run=^TestHTTPLoad$ -http_requests_threshold "$http_requests_threshold"; then
	http_result=1
fi

if ! ./ultimate-test-harness.test -test.v -test.run=^TestDNSLoad$ -dns_requests_threshold "$dns_requests_threshold"; then
	dns_result=1
fi
if [[ $http_result -eq 0 && $dns_result -eq 0 ]]; then echo
	echo Tests passed!
else
	exit_code=$?
	echo Tests failed!
	exit $exit_code
fi
