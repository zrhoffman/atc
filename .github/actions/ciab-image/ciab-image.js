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
const fs = require("fs");

fs.mkdirSync("ciab-images");
process.chdir("infrastructure/cdn-in-a-box");

const spawnArgs = {
	stdio: "inherit",
	stderr: "inherit",
	/* Use Docker BuildKit for better performance */
	env: Object.assign({
		DOCKER_BUILDKIT: "1",
		COMPOSE_DOCKER_CLI_BUILD: "1",
		XZ_OPT: "-9",
	}, process.env),
};

function splitEnvironmentVariable(name) {
	if (typeof process.env[name] !== "string" || process.env[name].length === 0) {
		throw new Error(`Missing environment variable ${name}`);
	}
	return process.env[name].split(",");
}

/* Empty the docker directory before starting */
let pruneProc = child_process.spawnSync(
	"docker",
	["image", "prune", "--all", "--force"],
	spawnArgs
);
if (pruneProc.status !== 0) {
	console.error("Unable to prune docker images");
	process.exit(pruneProc.status);
}

let rpmPaths;
try {
	rpmPaths = splitEnvironmentVariable("RPM_PATHS");
} catch (error) {
	console.log(`Not placing any RPMs: ${error.message}`);
}
if (rpmPaths instanceof Array) {
	const makeProc = child_process.spawnSync(
		"make",
		rpmPaths
	);
	if (makeProc.status !== 0) {
		console.error("Unable to place RPMs " + rpmPaths.join(", "));
		process.exit(pruneProc.status);
	}
}

const ciabImages = splitEnvironmentVariable("CIAB_IMAGES").map(service => service.replace(/_/g, ''));
const dockerComposeBuild = child_process.spawnSync(
	"docker-compose",
	["-f", "docker-compose.yml", "-f", "docker-compose.readiness.yml", "build", "--parallel", ...ciabImages],
	spawnArgs
);
if (dockerComposeBuild.status !== 0) {
	console.error("Unable to build CDN-in-a-Box images " + ciabImages.join(", "));
	process.exit(dockerComposeBuild.status);
}

const atcComponent = splitEnvironmentVariable("ATC_COMPONENT")[0];

/* Make a gzipped tar of the docker images */
console.log("Tarring the CDN-in-a-Box Docker images...");
const tarProc = child_process.spawnSync(
	"sh",
	["-c", `docker image ls --format={{.Repository}} | xargs docker image save -o ${process.env.GITHUB_WORKSPACE}/ciab-images/docker-${atcComponent}.tar.gz`],
	spawnArgs
);
if (tarProc.status !== 0) {
	console.error(`Unable to tar Docker data root directory`);
	process.exit(tarProc.status);
}
