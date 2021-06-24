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

import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.IOException

class TrafficOpsUtils {
    private var username: String? = null
    private var password: String? = null
    private var hostname: String? = null
    private var cdnName: String? = null
    private var config: JsonNode? = null
    fun replaceTokens(input: String?): String? {
        return input.replace("\${tmHostname}", getHostname()).replace("\${toHostname}", getHostname())
            .replace("\${cdnName}", getCdnName())
    }

    @Throws(JsonUtilsException::class)
    fun getUrl(parameter: String?): String? {
        return replaceTokens(JsonUtils.getString(config, parameter))
    }

    fun getUrl(parameter: String?, defaultValue: String?): String? {
        return if (config != null) replaceTokens(JsonUtils.optString(config, parameter, defaultValue)) else defaultValue
    }

    @Throws(IOException::class)
    fun getAuthJSON(): JsonNode? {
        val authMap: MutableMap<String?, String?> =
            HashMap()
        authMap["u"] = getUsername()
        authMap["p"] = getPassword()
        val mapper = ObjectMapper()
        return mapper.valueToTree(authMap)
    }

    fun getAuthUrl(): String? {
        return getUrl("api.auth.url", "https://\${toHostname}/api/2.0/user/login")
    }

    fun getUsername(): String? {
        return username
    }

    fun setUsername(username: String?) {
        this.username = username
    }

    fun getPassword(): String? {
        return password
    }

    fun setPassword(password: String?) {
        this.password = password
    }

    fun getHostname(): String? {
        return hostname
    }

    fun setHostname(hostname: String?) {
        this.hostname = hostname
    }

    fun getCdnName(): String? {
        return cdnName
    }

    fun setCdnName(cdnName: String?) {
        this.cdnName = cdnName
    }

    fun setConfig(config: JsonNode?) {
        this.config = config
    }

    fun getConfigLongValue(name: String?, defaultValue: Long): Long {
        return JsonUtils.optLong(config, name, defaultValue)
    }
}