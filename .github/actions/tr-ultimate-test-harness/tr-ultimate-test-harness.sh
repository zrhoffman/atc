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

export DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 # build Docker images faster

trap 'echo "Error on line ${LINENO} of ${0}"; exit 1' ERR;
set -o xtrace
set -o errexit -o nounset -o pipefail
docker-compose up -d

# Constants
declare -r cookie_name=dev-ciab-cookie

# Set TO_USER, TO_PASSWORD, and TO_URL environment variables and get atc-ready function
source dev/atc.dev.sh

export -f atc-ready
echo 'Waiting until Traffic Ops is ready to accept requests...'
if ! timeout 10m bash -c 'atc-ready -w'; then
	echo 'Traffic Ops was not available within 10 minutes!'
	trap - ERR
	echo 'Exiting...'
	exit 1
fi

to-req() {
	endpoint="$1"
	shift
	local curl_command=(curl --insecure --silent --cookie-jar "$cookie_name" --cookie "$cookie_name" "${TO_URL}/api/${API_VERSION}")
	"${curl_command[@]}${endpoint}" "$@" | jq
}

# Log in
login_body="$(<<<{} jq --arg TO_USER "$TO_USER" --arg TO_PASSWORD "$TO_PASSWORD" '.u = $TO_USER | .p = $TO_PASSWORD')"
to-req /user/login --data "$login_body"

declare -A service_by_hostname
service_by_hostname[trafficrouter]=trafficrouter
service_by_hostname[edge]=t3c

for hostname in trafficrouter edge; do
	container_id="$(docker-compose ps -q "${service_by_hostname[$hostname]}")"
	interface="$(<<'JSON' jq
	{
		"mtu": 1500,
		"monitor": true,
		"ipAddresses": [],
		"name": "eth0"
	}
JSON
	)"
	docker_network="$(docker network inspect dev.ciab.test)"
	for ip_address_field in IPv4Address IPv6Address; do
		ip_address="$(<<<"$docker_network" jq -r --arg CONTAINER_ID "$container_id" --arg IP_ADDRESS_FIELD "$ip_address_field" '.[0].Containers[$CONTAINER_ID][$IP_ADDRESS_FIELD]')"
		if [[ "$ip_address" == null ]]; then
			echo "Could not find ${ip_address_field} for ${hostname} service!"
			#exit 1
		fi
		interface="$(<<<"$interface" jq --arg IP_ADDRESS "$ip_address" '.ipAddresses += [{} | .address = $IP_ADDRESS | .serviceAddress = true]')"
	done


	# Get Traffic Router server JSON
	server="$(to-req "/servers?hostName=${hostname}" | jq '.response[0]')"
	if [[ -z "$server" ]]; then
		echo "Could not get JSON for server ${hostname}"
		exit 1
	fi

	# Update Traffic Router's interface with its IP addresses
	server="$(<<<"$server" jq ".interfaces = [${interface}]")"
	server_id="$(<<<"$server" jq .id)"
	if ! to-req "/servers/${server_id}" --request PUT --data "$server"; then
		echo "Could not update server ${hostname} with ${server}"
	fi
done

# Snapshot
cdn_id="$(<<<"$server" jq .cdnId)"
to-req "/snapshot?cdnID=${cdn_id}" --request PUT

deliveryservice=cdn.dev-ds.ciab.test
echo "Waiting for Delivery Service ${deliveryservice} to be available..."

if ! timeout 2m <<SHELL_COMMANDS docker-compose exec -T trafficops sh; then
	set -o errexit
	until curl -4sfH "Host: ${deliveryservice}" trafficrouter:3333/crs/stats &&
					echo "\$(dig +short -4 @trafficrouter "$deliveryservice")" | grep -q '^[0-9.]\+$';
	do
		sleep 1;
	done
SHELL_COMMANDS
	if docker-compose run --rm --no-deps trafficops curl -v4sfH "Host: ${deliveryservice}" trafficrouter:3333/crs/stats; then
		echo curl worked;
	else
		echo curl did not work;
	fi
	if docker-compose run --rm --no-deps trafficops dig -4 @trafficrouter "$deliveryservice"; then
		echo dig worked;
	else
		echo dig did not work;
	fi
	echo "Delivery Service ${deliveryservice} was not available within 2 minutes!"
	trap - ERR
	echo 'Exiting...'
	exit 1
fi

http_result=0 dns_result=0
# Compile the tests
go test -c ./traffic_router/ultimate-test-harness
ultimate_test_harness_command=(docker-compose exec --workdir=/root/go/src/github.com/apache/trafficcontrol --env TO_URL=https://trafficops --env TO_USER="$TO_USER" --env TO_PASSWORD="$TO_PASSWORD" trafficops ./ultimate-test-harness.test)
if ! "${ultimate_test_harness_command[@]}" -test.v -test.run=^TestHTTPLoad$ -http_requests_threshold=5000; then
	http_result=1
fi

if ! "${ultimate_test_harness_command[@]}" -test.v -test.run=^TestDNSLoad$ -dns_requests_threshold=20500; then
	dns_result=1
fi
if [[ $http_result -eq 0 && $dns_result -eq 0 ]]; then echo
	echo Tests passed!
else
	exit_code=$?
	echo Tests failed!
	exit $exit_code
fi
