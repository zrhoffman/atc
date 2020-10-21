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
let spawnOptions = {
    stdio: "inherit",
};
const atcComponent = process.env.ATC_COMPONENT;
const dockerComposeArgs = ["-f", `${process.env.GITHUB_WORKSPACE}/infrastructure/docker/build/docker-compose.yml`, "run", "--rm"];
if (!atcComponent) {
    console.error("Missing environment variable ATC_COMPONENT");
    process.exit(1);
}
dockerComposeArgs.push(atcComponent + "_build");
const proc = child_process_1.default.spawnSync("docker-compose", dockerComposeArgs, spawnOptions);
process.exit(proc.status || 1);
