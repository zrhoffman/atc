/*
 *
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
package com.comcast.cdn.traffic_control.traffic_router.core.util

import java.io.File

object Config {
    private val confDir: String? = null
    private val varDir: String? = null
    fun getConfDir(): String? {
        return Config.confDir
    }

    fun getVarDir(): String? {
        return Config.varDir
    }

    init {
        Config.confDir = "src/test/resources/var/"
        if (File("/opt/traffic_router/conf").exists()) {
            Config.confDir = "/opt/traffic_router/conf/"
        }
        Config.varDir = "src/test/resources/var/"
        if (File("/opt/traffic_router").exists()) {
            Config.varDir = "/opt/traffic_router/var/"
        }
    }
}