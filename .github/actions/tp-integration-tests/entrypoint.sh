#!/bin/bash
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
trap 'echo "Error on line ${LINENO} of ${0}"; exit 1' ERR
set -o errexit -o nounset -o pipefail

hub_fqdn="http://localhost:4444/wd/hub/status"
to_fqdn="https://localhost:6443"
tp_fqdn="https://172.18.0.1:8443"

if ! curl -Lvsk "${hub_fqdn}" >/dev/null 2>&1; then
  echo "Selenium not started on ${hub_fqdn}"
  exit 1
fi

export PGUSER="traffic_ops"
export PGPASSWORD="twelve"
export PGHOST="localhost"
export PGDATABASE="traffic_ops"
export PGPORT="5432"

# For TV Setup
DIVISION="adivision"
REGION="aregion"
PHYS="aloc"
COORD="acoord"
CDN="zcdn"
CG="acg"
<<QUERY psql
INSERT INTO tm_user (username, role, tenant_id, local_passwd)
  VALUES ('admin', 1, 1,
    'SCRYPT:16384:8:1:vVw4X6mhoEMQXVGB/ENaXJEcF4Hdq34t5N8lapIjDQEAS4hChfMJMzwwmHfXByqUtjmMemapOPsDQXG+BAX/hA==:vORiLhCm1EtEQJULvPFteKbAX2DgxanPhHdrYN8VzhZBNF81NRxxpo7ig720KcrjH1XFO6BUTDAYTSBGU9KO3Q=='
  );
INSERT INTO division(name) VALUES('${DIVISION}');
INSERT INTO region(name, division) VALUES('${REGION}', 1);
INSERT INTO phys_location(name, short_name, region, address, city, state, zip)
  VALUES('${PHYS}', '${PHYS}', 1, 'some place idk', 'Denver', 'CO', '88888');
INSERT INTO coordinate(name) VALUES('${COORD}');
INSERT INTO cdn(name, domain_name) VALUES('${CDN}', 'infra.ciab.test');
WITH TYPE AS (SELECT id FROM type WHERE name = 'TC_LOC')
INSERT INTO cachegroup(name, short_name, type, coordinate)
SELECT '${CG}', '${CG}', TYPE.id, 1
FROM TYPE;
QUERY

sudo useradd trafops

download_go() {
	. build/functions.sh
	if verify_and_set_go_version; then
		return
	fi
	go_version="$(cat "${GITHUB_WORKSPACE}/GO_VERSION")"
	wget -O go.tar.gz "https://dl.google.com/go/go${go_version}.linux-amd64.tar.gz" --no-verbose
	echo "Extracting Go ${go_version}..."
	<<-'SUDO_COMMANDS' sudo sh
		set -o errexit
    go_dir="$(command -v go | xargs realpath | xargs dirname | xargs dirname)"
		mv "$go_dir" "${go_dir}.unused"
		tar -C /usr/local -xzf go.tar.gz
	SUDO_COMMANDS
	rm go.tar.gz
	go version
}

gray_bg="$(printf '%s%s' $'\x1B' '[100m')";
red_bg="$(printf '%s%s' $'\x1B' '[41m')";
yellow_bg="$(printf '%s%s' $'\x1B' '[43m')";
black_fg="$(printf '%s%s' $'\x1B' '[30m')";
color_and_prefix() {
	color="$1";
	shift;
	prefix="$1";
	normal_bg="$(printf '%s%s' $'\x1B' '[49m')";
	normal_fg="$(printf '%s%s' $'\x1B' '[39m')";
	sed "s/^/${color}${black_fg}${prefix}: /" | sed "s/$/${normal_bg}${normal_fg}/";
}

ciab_dir="${GITHUB_WORKSPACE}/infrastructure/cdn-in-a-box";

sudo apt-get install -y --no-install-recommends gettext \
	ruby ruby-dev libc-dev curl \
	gcc

sudo gem install sass compass
sudo npm i -g forever bower grunt

CHROMIUM_CONTAINER=$(docker ps -qf name=chromium)
HUB_CONTAINER=$(docker ps -qf name=hub)
CHROMIUM_VER=$(docker exec "$CHROMIUM_CONTAINER" chromium --version | grep -Eo '[0-9.]+')

GOROOT=/usr/local/go
export PATH="${PATH}:${GOROOT}/bin"
download_go
export GOPATH="${HOME}/go"
readonly ORG_DIR="$GOPATH/src/github.com/apache"
readonly REPO_DIR="${ORG_DIR}/trafficcontrol"
resources="$(dirname "$0")"
if [[ ! -e "$REPO_DIR" ]]; then
	mkdir -p "$ORG_DIR"
	cd
	mv "${GITHUB_WORKSPACE}" "${REPO_DIR}/"
	ln -s "$REPO_DIR" "${GITHUB_WORKSPACE}"
fi

to_build() {
  cd "${REPO_DIR}/traffic_ops/traffic_ops_golang"
  go mod vendor -v
  go build .

  openssl req -new -x509 -nodes -newkey rsa:4096 -out localhost.crt -keyout localhost.key -subj "/CN=tptests";

  envsubst <"${resources}/cdn.json" >cdn.conf
  cp "${resources}/database.json" database.conf

  export $(<"${ciab_dir}/variables.env" sed '/^#/d') # defines TV_ADMIN_USER/PASSWORD
  truncate --size=0 warning.log error.log event.log info.log

  ./traffic_ops_golang --cfg ./cdn.conf --dbcfg ./database.conf &
  tail -f warning.log 2>&1 | color_and_prefix "${yellow_bg}" 'Traffic Ops WARN' &
  tail -f error.log 2>&1 | color_and_prefix "${red_bg}" 'Traffic Ops ERR' &
  tail -f event.log 2>&1 | color_and_prefix "${gray_bg}" 'Traffic Ops EVT' &
}

tp_build() {
  cd "${REPO_DIR}/traffic_portal"
  npm ci
  bower install
  grunt dist

  cp "${resources}/config.js" ./conf/
  touch tp.log access.log out.log err.log
  sudo forever --minUptime 5000 --spinSleepTime 2000 -f -o out.log start server.js &
  tail -f err.log 2>&1 | color_and_prefix "${red_bg}" "Node Err" &
}

(to_build) &
(tp_build) &

onFail() {
  mv tp.log Reports/forever.log
  mv access.log Reports/tp-access.log
  mv out.log Reports/node.log
  docker logs $CHROMIUM_CONTAINER > Reports/chromium.log
  docker logs $HUB_CONTAINER > Reports/hub.log
  echo "Detailed logs produced info Reports artifact"
  exit 1
}


cd "${REPO_DIR}/traffic_portal/test/integration"
npm ci
PATH=$(pwd)/node_modules/.bin/:$PATH

webdriver-manager update --gecko false --versions.chrome "LATEST_RELEASE_$CHROMIUM_VER"

jq " .capabilities.chromeOptions.args = [
    \"--headless\",
    \"--no-sandbox\",
    \"--disable-gpu\",
    \"--ignore-certificate-errors\"
  ] | .params.apiUrl = \"${tp_fqdn}/api/4.0\" | .params.baseUrl =\"${tp_fqdn}\"
  | .capabilities[\"goog:chromeOptions\"].w3c = false | .capabilities.chromeOptions.w3c = false" \
  config.json > config.json.tmp && mv config.json.tmp config.json

tsc

# Wait for tp/to build
timeout 5m bash <<TMOUT
  while ! curl -Lvsk "${tp_fqdn}/api/4.0/ping" >/dev/null 2>&1; do
    echo "waiting for TP/TO server to start on '${tp_fqdn}'"
    sleep 10
  done
TMOUT

trap - ERR
protractor ./GeneratedCode/config.js --params.baseUrl="${tp_fqdn}" --params.apiUrl="${to_fqdn}/api/4.0" || onFail
