#!/usr/bin/env sh
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# shellcheck shell=ash
trap 'exit_code=$?; [ $exit_code -ne 0 ] && echo "Error on line ${LINENO} of ${0}"; cleanup; exit $exit_code' EXIT;
set -o errexit -o nounset;


# Fix ownership of output files
#  $1 is file or dir with correct ownership
#  remaining args are files/dirs to be fixed, recursively
setowner() {
	own=$(stat -c '%u:%g' "$1")
	shift
	[ -n "$*" ] && chown -R "${own}" "$@"
}

cleanup() {
	setowner /trafficcontrol /trafficcontrol/dist
}

set -o xtrace;

# set owner of dist dir -- cleans up existing dist permissions...
export GOPATH=/tmp/go;
tc_dir=${GOPATH}/src/github.com/apache/trafficcontrol;
for dir in src pkg bin; do
	mkdir -p "${GOPATH}/${dir}";
done
mkdir -p  "$tc_dir";
(cp -fa /trafficcontrol "$(dirname "$tc_dir")"
	if ! [ -d ${tc_dir}/.git ]; then
		cp -fa /trafficcontrol/.git $tc_dir # Docker for Windows compatibility
	fi;
	rm -rf "${tc_dir}/dist";
	mkdir -p /trafficcontrol/dist;
	ln -s /trafficcontrol/dist "${tc_dir}/dist") && \
	cd "$tc_dir" &&
	( ( ( (./build/build.sh "$1" 2>&1; echo $? >&3) | tee ./dist/build-"$1".log >&4) 3>&1) | (read -r x; exit "$x"); ) 4>&1
