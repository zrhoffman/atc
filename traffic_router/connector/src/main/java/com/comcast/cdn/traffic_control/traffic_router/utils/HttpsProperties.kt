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
package com.comcast.cdn.traffic_control.traffic_router.utils

import com.comcast.cdn.traffic_control.traffic_router.utils.HttpsProperties
import org.apache.log4j.Logger
import java.nio.file.Files
import java.nio.file.Paths
import java.util.function.Consumer

class HttpsProperties {
    private val httpsPropertiesMap: MutableMap<String?, String?>?
    fun getHttpsPropertiesMap(): MutableMap<String?, String?>? {
        return httpsPropertiesMap
    }

    companion object {
        private val log = Logger.getLogger(HttpsProperties::class.java)
        private val HTTPS_PROPERTIES_FILE: String? = "/opt/traffic_router/conf/https.properties"
        private fun loadHttpsProperties(): MutableMap<String?, String?>? {
            return try {
                val httpsProperties: MutableMap<String?, String?> = HashMap()
                Files.readAllLines(Paths.get(HttpsProperties.Companion.HTTPS_PROPERTIES_FILE)).forEach(
                    Consumer { propString: String? ->
                        if (!propString.startsWith("#")) { // Ignores comments in properties file
                            val prop: Array<String?> = propString.split("=".toRegex()).toTypedArray()
                            httpsProperties[prop[0]] = prop[1]
                        }
                    })
                httpsProperties
            } catch (e: Exception) {
                HttpsProperties.Companion.log.error("Error loading https properties file.")
                null
            }
        }
    }

    init {
        httpsPropertiesMap = HttpsProperties.Companion.loadHttpsProperties()
    }
}