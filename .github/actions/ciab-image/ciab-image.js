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
const path = require("path");

const spawnOptions = {
	stdio: "inherit",
	stderr: "inherit",
	/* Use Docker BuildKit for better performance */
	env: Object.assign({
		DOCKER_BUILDKIT: "1",
		COMPOSE_DOCKER_CLI_BUILD: "1",
	}, process.env),
};

function splitEnvironmentVariable(name, allowEmpty = false) {
	if (typeof process.env[name] === "string" && process.env[name].length > 0) {
		return process.env[name].split(",");
	}
	if (allowEmpty === true) {
		return [];
	}
	throw new Error(`Missing environment variable ${name}`);
}

const saveImages = process.env["SAVE_IMAGES"] === "true";

if (saveImages === true) {
	/* Empty the docker directory before starting */
	console.log("Removing existing Docker images...");
	const pruneProc = child_process.spawnSync(
		"docker",
		["image", "prune", "--all", "--force"],
		spawnOptions
	);
	if (pruneProc.status !== 0) {
		console.error("Unable to prune docker images");
		process.exit(pruneProc.status);
	}
}

const rpmPaths = splitEnvironmentVariable("RPM_PATHS", true);
process.chdir("dist");
const rpms = fs.readdirSync(".") // read contents of the dist directory
	.filter(item => fs.lstatSync(item).isDirectory()) // get a list of directories within dist
	.flatMap(directory => fs.readdirSync(directory).map(item => path.join(directory, item))) // list files within those directories
	.filter(item => /\.rpm$/.test(item)) // get a list of RPMs
	.map(rpm => {
		fs.renameSync(rpm, rpm.replace(new RegExp('.*/'), ''));
		return rpm;
	}); // move the RPMs to the dist folder
process.chdir("..");
if (rpms.length > 0) {
	console.log(`Moved ${rpms.length} RPMs to the dist directory: ${rpms.toString()}`);
}

fs.mkdirSync("ciab-images");
process.chdir("infrastructure/cdn-in-a-box");

const makeProc = child_process.spawnSync(
	"make",
	rpmPaths,
	spawnOptions
);
if (makeProc.status !== 0) {
	console.error("Unable to place RPMs " + rpmPaths.join(", "));
	process.exit(makeProc.status);
}

const ciabImages = splitEnvironmentVariable("CIAB_IMAGES").map(service => service.replace(/_/g, ''));
const dockerComposeBuild = child_process.spawnSync(
	"docker-compose",
	["-f", "docker-compose.yml", "-f", "docker-compose.readiness.yml", "build", "--parallel", ...ciabImages],
	spawnOptions
);
if (dockerComposeBuild.status !== 0) {
	console.error("Unable to build CDN-in-a-Box images " + ciabImages.join(", "));
	process.exit(dockerComposeBuild.status);
}

if (saveImages === true) {
	/* Make a gzipped tar of the docker images */
	console.log("Tarring the CDN-in-a-Box Docker images...");
	const tarProc = child_process.spawnSync(
		"sh",
		["-c", `docker image ls --format={{.Repository}} | xargs docker image save -o ${process.env.GITHUB_WORKSPACE}/ciab-images/docker-${process.env.GITHUB_JOB}.tar.gz`],
		spawnOptions
	);
	if (tarProc.status !== 0) {
		console.error("Unable to tar Docker data root directory");
		process.exit(tarProc.status);
	}
}