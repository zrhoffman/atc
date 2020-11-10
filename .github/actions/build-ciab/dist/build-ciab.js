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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = __importDefault(require("child_process"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const spawnOptions = { stdio: "inherit" };
const dockerCompose = ["docker-compose", "-f", "docker-compose.yml", "-f", "docker-compose.readiness.yml"];
process.env.DOCKER_BUILDKIT = "1";
process.env.COMPOSE_DOCKER_CLI_BUILD = "1";
function runProcess(...commandArguments) {
    var _a;
    console.info(...commandArguments);
    const proc = child_process_1.default.spawnSync(commandArguments[0], commandArguments.slice(1), spawnOptions);
    if (proc.status === 0) {
        return;
    }
    console.error("Child process", ...commandArguments, "exited with status code", proc.status, "!");
    process.exit((_a = proc.status) !== null && _a !== void 0 ? _a : 1);
}
function splitEnvironmentVariable(name, allowEmpty = false) {
    const value = process.env[name];
    if (typeof value !== "undefined" && value.length > 0) {
        return value.split(",");
    }
    if (allowEmpty) {
        return [];
    }
    throw new Error(`Missing environment variable ${name}`);
}
function moveRPMs() {
    const rpmPaths = splitEnvironmentVariable("INPUT_RPM_PATHS", true);
    if (rpmPaths.length === 0) {
        return;
    }
    process.chdir(`${process.env.GITHUB_WORKSPACE}/dist`);
    fs_1.default.readdirSync(".") // read contents of the dist directory
        .filter(item => fs_1.default.lstatSync(item).isDirectory()) // get a list of directories within dist
        .flatMap((directory) => fs_1.default.readdirSync(directory).map(item => path_1.default.join(directory, item))) // list files within those directories
        .filter((item) => /\.rpm$/.test(item)) // get a list of RPMs
        .forEach((rpm) => fs_1.default.renameSync(rpm, path_1.default.basename(rpm))); // move the RPMs to the dist folder
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
    fs_1.default.mkdirSync(`${process.env.GITHUB_WORKSPACE}/ciab-images`);
    /* Make a gzipped tar of the docker images */
    console.log("Tarring the CDN-in-a-Box Docker images...");
    runProcess("sh", "-c", "docker image ls --format={{.Repository}} | " +
        `xargs docker image save -o ${process.env.GITHUB_WORKSPACE}/ciab-images/docker-${process.env.GITHUB_JOB}.tar.gz`);
}
