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
package com.comcast.cdn.traffic_control.traffic_router.core.monitor

import com.comcast.cdn.traffic_control.traffic_router.core.util.ResourceUrl

internal class TrafficMonitorResourceUrl(
    private val trafficMonitorWatcher: TrafficMonitorWatcher?,
    private val urlTemplate: String?
) : ResourceUrl {
    private var i = 0
    override fun nextUrl(): String? {
        val hosts = trafficMonitorWatcher.getHosts()
        if (hosts == null || hosts.size == 0) {
            return urlTemplate
        }
        i %= hosts.size
        val host = hosts[i]
        i++
        return urlTemplate.replace("[host]", host)
    }
}