/*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

const child_process = require("child_process");
const spawnArgs = {
	stdio: "inherit",
	stderr: "inherit",
	/* Use Docker BuildKit for better performance */
	env: Object.assign({DOCKER_BUILDKIT: "1", COMPOSE_DOCKER_CLI_BUILD: "1"}, process.env),
};

const installSetupTools = child_process.spawnSync(
	'python3',
	['-m', 'pip', 'install', '--upgrade', 'setuptools'],
	spawnArgs
);
if (installSetupTools.status !== 0) {
	console.error('Unable to install pip');
	process.exit(installSetupTools.status);
}

const installPip = child_process.spawnSync(
	'python3',
	['-m', 'pip', 'install', '--upgrade', 'docker-compose'],
	spawnArgs
);
if (installPip.status !== 0) {
	console.error('Unable to install pip');
	process.exit(installPip.status);
}

const proc = child_process.spawnSync(
	`${process.env.GITHUB_WORKSPACE}/infrastructure/docker/build/build-rpms.py`,
	[],
	spawnArgs
);
process.exit(proc.status);
