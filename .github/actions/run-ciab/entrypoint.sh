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

set -ex

export COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 # use Docker BuildKit for better performance

(
# Load CDN-in-a-Box docker images from GitHub Actions artifacts
cd ciab-images;
for image_set in *-images; do
  docker image load -i "${image_set}/docker-"*.tar.gz;
done;
)

docker-compose --version;
STARTING_POINT="$PWD";
cd infrastructure/cdn-in-a-box;

docker images;
docker_compose='docker-compose -f ./docker-compose.yml -f ./docker-compose.readiness.yml';
time $docker_compose up -d edge mid origin trafficops trafficops-perl dns enroller trafficrouter trafficstats trafficvault trafficmonitor;
$docker_compose logs -f edge mid origin trafficops trafficops-perl dns enroller trafficrouter trafficstats trafficvault trafficmonitor &

if ! timeout 10m $docker_compose up --exit-code-from=readiness readiness; then
	echo "CDN in a Box didn't become ready within 10 minutes - exiting" >&2;
	docker-compose -f ./docker-compose.yml -f ./docker-compose.readiness.yml down -v --remove-orphans;
	exit 1;
fi

docker-compose -f ./docker-compose.yml -f ./docker-compose.readiness.yml down -v --remove-orphans;
