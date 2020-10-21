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

"use strict"
import child_process, {SpawnSyncOptions} from "child_process"

let spawnOptions: SpawnSyncOptions = {
    stdio: "inherit",
}

const atcComponent = process.env.ATC_COMPONENT
const dockerComposeArgs = ["-f", `${process.env.GITHUB_WORKSPACE}/infrastructure/docker/build/docker-compose.yml`, "run", "--rm"]
if (!atcComponent) {
    console.error("Missing environment variable ATC_COMPONENT")
    process.exit(1)
}

const subprocesses = atcComponent
    .split(",")
    .map(component => component + "_build")
    .map(service => child_process.spawn(
        "docker-compose",
        [...dockerComposeArgs, service],
        spawnOptions
    ))

let completedCount = 0

function countCompleted(): void {
    completedCount++
    if (completedCount !== subprocesses.length) {
        return
    }
    console.log("All components built successfully!")
    process.exit(0)
}

subprocesses.forEach(subprocess => subprocess.on("exit", exitCode => {
        const component = subprocess.spawnargs.pop()
        if (exitCode !== 0) {
            console.error(component, "failed with exit code ", exitCode)
            process.exit(exitCode || 1)
        }
        console.log("Finished building", component)
        countCompleted()
    }
))
