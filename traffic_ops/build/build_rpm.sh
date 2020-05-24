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
trap 'exit_code=$?; [ $exit_code -ne 0 ] && echo "Error on line ${LINENO} of ${0}" >/dev/stderr; exit $exit_code' EXIT;
set -o errexit -o nounset -o pipefail;

#----------------------------------------
importFunctions() {
	local script scriptdir
	script="$(readlink -f "$0")"
	scriptdir="$(dirname "$script")"
	TO_DIR='' TC_DIR=''
	TO_DIR="$(dirname "$scriptdir")"
	TC_DIR="$(dirname "$TO_DIR")"
	export TO_DIR TC_DIR
	functions_sh="$TC_DIR/build/functions.sh"
	if [ ! -r "$functions_sh" ]; then
		echo "error: can't find $functions_sh"
		return 1
	fi
	. "$functions_sh"
}

# ---------------------------------------
initBuildArea() {
	echo "Initializing the build area."
	mkdir -p "$RPMBUILD"/{SPECS,SOURCES,RPMS,SRPMS,BUILD,BUILDROOT} || { echo "Could not create $RPMBUILD: $?"; return 1; }

	local to_dest
	to_dest="$(createSourceDir traffic_ops)"
	cd "$TO_DIR" || \
		 { echo "Could not cd to $TO_DIR: $?"; return 1; }

	echo "PATH: $PATH"
	echo "GOPATH: $GOPATH"
	go version
	go env

	# get x/* packages (everything else should be properly vendored)
	go get -v golang.org/x/crypto/ed25519 golang.org/x/crypto/scrypt golang.org/x/net/ipv4 golang.org/x/net/ipv6 golang.org/x/sys/unix || \
		{ echo "Could not get go package dependencies"; return 1; }

	# compile traffic_ops_golang
	pushd traffic_ops_golang
	go_build=(go build -v);
	if [[ "$DEBUG_BUILD" == true ]]; then
		echo 'DEBUG_BUILD is enabled, building without optimization or inlining...';
		go_build+=(-gcflags 'all=-N -l');
	fi;
	"${go_build[@]}" -ldflags "-X main.version=traffic_ops-${TC_VERSION}-${BUILD_NUMBER}.${RHEL_VERSION} -B 0x$(git rev-parse HEAD)" || \
								{ echo "Could not build traffic_ops_golang binary"; return 1; }
	popd

	# compile db/admin
	pushd app/db
	"${go_build[@]}" -o admin || \
								{ echo "Could not build db/admin binary"; return 1; }
	popd

	# compile TO profile converter
	pushd install/bin/convert_profile
	"${go_build[@]}" || \
								{ echo "Could not build convert_profile binary"; return 1; }
	popd

	# compile atstccfg
	pushd ort/atstccfg
	"${go_build[@]}" -ldflags "-X main.GitRevision=`git rev-parse HEAD` -X main.BuildTimestamp=`date +'%Y-%M-%dT%H:%M:%s'` -X main.Version=${TC_VERSION}" || \
								{ echo "Could not build atstccfg binary"; return 1; }
	popd

	rsync -av etc install "$to_dest"/ || \
		 { echo "Could not copy to $to_dest: $?"; return 1; }
	rsync -av app/{bin,conf,cpanfile,db,lib,public,script,templates} "$to_dest"/app/ || \
		 { echo "Could not copy to $to_dest/app: $?"; return 1; }
	tar -czvf "$to_dest".tgz -C "$RPMBUILD"/SOURCES "$(basename "$to_dest")" || \
		 { echo "Could not create tar archive $to_dest.tgz: $?"; return 1; }
	cp "$TO_DIR"/build/*.spec "$RPMBUILD"/SPECS/. || \
		 { echo "Could not copy spec files: $?"; return 1; }

	# Create traffic_ops_ort source area
	to_ort_dest=$(createSourceDir traffic_ops_ort)
	cp -p ort/traffic_ops_ort.pl "$to_ort_dest"
	cp -p ort/supermicro_udev_mapper.pl "$to_ort_dest"
	mkdir -p "${to_ort_dest}/atstccfg"
	cp -R -p ort/atstccfg/* "${to_ort_dest}/atstccfg"

	tar -czvf "$to_ort_dest".tgz -C "$RPMBUILD"/SOURCES "$(basename "$to_ort_dest")" || \
		 { echo "Could not create tar archive $to_ort_dest: $?"; return 1; }

	PLUGINS=''
	PLUGINS="$(grep -l 'AddPlugin(' "${TO_DIR}/traffic_ops_golang/plugin/"*.go |
		grep -v 'func AddPlugin(' |
		xargs -I '{}' basename {} '.go'
	)"
	export PLUGINS

	echo "The build area has been initialized."
}

# ---------------------------------------
importFunctions
checkEnvironment go
initBuildArea
buildRpm traffic_ops traffic_ops_ort
