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

const entrypointProc = child_process.spawnSync(
	`${__dirname}/entrypoint.sh`,
	[],
	spawnArgs
);
process.exit(entrypointProc.status);