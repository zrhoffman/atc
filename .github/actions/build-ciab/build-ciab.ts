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

"use strict";
import child_process, { SpawnSyncOptions } from "child_process";
import fs from "fs";
import path from "path";

const spawnOptions: SpawnSyncOptions = {stdio: "inherit"};
const dockerCompose = ["docker-compose", "-f", "docker-compose.yml", "-f", "docker-compose.readiness.yml"];
process.env.DOCKER_BUILDKIT = "1";
process.env.COMPOSE_DOCKER_CLI_BUILD = "1";

function runProcess(...commandArguments: string[]): void {
	console.info(...commandArguments);
	const proc = child_process.spawnSync(
		commandArguments[0],
		commandArguments.slice(1),
		spawnOptions
	);
	if (proc.status === 0) {
		return;
	}
	console.error("Child process", ...commandArguments, "exited with status code", proc.status, "!");
	process.exit(proc.status ?? 1);
}

function splitEnvironmentVariable(name: string, allowEmpty: boolean = false): string[] {
	const value: string | undefined = process.env[name];
	if (typeof value !== "undefined" && value.length > 0) {
		return value.split(",");
	}
	if (allowEmpty) {
		return [];
	}
	throw new Error(`Missing environment variable ${name}`);
}

function moveRPMs(): void {
	const rpmPaths = splitEnvironmentVariable("INPUT_RPM_PATHS", true);
	if (rpmPaths.length === 0) {
		process.chdir(`${process.env.GITHUB_WORKSPACE}/infrastructure/cdn-in-a-box`);
		return;
	}

	process.chdir(`${process.env.GITHUB_WORKSPACE}/dist`);
	fs.readdirSync(".") // read contents of the dist directory
		.filter(item => fs.lstatSync(item).isDirectory()) // get a list of directories within dist
		.flatMap((directory: string) =>
			fs.readdirSync(directory).map(item => path.join(directory, item))) // list files within those directories
		.filter((item: string) => /\.rpm$/.test(item)) // get a list of RPMs
		.forEach((rpm: string) => fs.renameSync(rpm, path.basename(rpm))); // move the RPMs to the dist folder

	// Place the RPMs for docker-compose build. All RPMs should have already been built.
	process.chdir(`${process.env.GITHUB_WORKSPACE}/infrastructure/cdn-in-a-box`);
	runProcess("make", ...rpmPaths);
}

const saveImages = process.env.INPUT_SAVE_IMAGES === "true";
if (saveImages) {
	/* Empty the docker directory before starting */
	console.log("Removing existing Docker images...");
	runProcess("docker", "image", "prune", "--all", "--force");
}

moveRPMs();
const ciabImages = splitEnvironmentVariable("INPUT_CIAB_IMAGES").map(service => service.replace(/_/g, ""));
runProcess(...dockerCompose, "-f", "docker-compose.yml", "-f", "docker-compose.readiness.yml", "build", "--parallel", ...ciabImages);

if (saveImages) {
	fs.mkdirSync(`${process.env.GITHUB_WORKSPACE}/ciab-images`);
	/* Make a gzipped tar of the docker images */
	console.log("Tarring the CDN-in-a-Box Docker images...");
	runProcess("sh", "-c", "docker image ls --format={{.Repository}} | " +
		`xargs docker image save -o ${process.env.GITHUB_WORKSPACE}/ciab-images/docker-${process.env.GITHUB_JOB}.tar.gz`);
}
