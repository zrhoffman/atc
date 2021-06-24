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
package com.comcast.cdn.traffic_control.traffic_router.api.controllers

import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node.IPVersions
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody

@Controller
@RequestMapping("/coveragezone")
class CoverageZoneController {
    @Autowired
    var trafficRouterManager: TrafficRouterManager? = null

    @RequestMapping(value = ["/cachelocation"])
    @ResponseBody
    fun getCacheLocationForIp(
        @RequestParam(name = "ip") ip: String?,
        @RequestParam(name = "deliveryServiceId") deliveryServiceId: String?
    ): ResponseEntity<CacheLocation?>? {
        val requestVersion = if (ip.contains(":")) IPVersions.IPV6ONLY else IPVersions.IPV4ONLY
        val cacheLocation =
            trafficRouterManager.getTrafficRouter().getCoverageZoneCacheLocation(ip, deliveryServiceId, requestVersion)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null)
        return ResponseEntity.ok(cacheLocation)
    }

    @RequestMapping(value = ["/caches"])
    @ResponseBody
    fun getCachesForDeliveryService(
        @RequestParam(name = "deliveryServiceId") deliveryServiceId: String?,
        @RequestParam(name = "cacheLocationId") cacheLocationId: String?
    ): ResponseEntity<MutableList<Cache?>?>? {
        val caches = trafficRouterManager.getTrafficRouter()
            .selectCachesByCZ(deliveryServiceId, cacheLocationId, null, IPVersions.ANY)
        return if (caches == null || caches.isEmpty()) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(null)
        } else ResponseEntity.ok(caches)
    }
}