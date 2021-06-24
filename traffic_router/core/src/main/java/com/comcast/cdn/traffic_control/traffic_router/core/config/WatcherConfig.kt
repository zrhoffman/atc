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
package com.comcast.cdn.traffic_control.traffic_router.core.config

import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.fasterxml.jackson.databind.JsonNode

class WatcherConfig(prefix: String?, config: JsonNode?, trafficOpsUtils: TrafficOpsUtils?) {
    private val url: String?
    private val interval: Long

    // this is an int instead of a long because of protected resource fetcher
    private val timeout: Int
    fun getInterval(): Long {
        return interval
    }

    fun getUrl(): String? {
        return url
    }

    fun getTimeout(): Int {
        return timeout
    }

    init {
        url = trafficOpsUtils.getUrl("$prefix.polling.url", "")
        interval = JsonUtils.optLong(config, "$prefix.polling.interval", -1L)
        timeout = JsonUtils.optInt(config, "$prefix.polling.timeout", -1)
    }
}