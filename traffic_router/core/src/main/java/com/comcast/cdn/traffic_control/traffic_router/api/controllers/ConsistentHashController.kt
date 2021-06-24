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

import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseBody

@Controller
@RequestMapping("/consistenthash")
class ConsistentHashController {
    @Autowired
    var trafficRouterManager: TrafficRouterManager? = null

    @RequestMapping(value = ["/cache/coveragezone"])
    @ResponseBody
    fun hashCoverageZoneCache(
        @RequestParam(name = "ip") ip: String?,
        @RequestParam(name = ConsistentHashController.Companion.DELIVERY_SERVICE_ID) deliveryServiceId: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<*>? {
        val cache =
            trafficRouterManager.getTrafficRouter().consistentHashForCoverageZone(ip, deliveryServiceId, requestPath)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}")
        return ResponseEntity.ok(cache)
    }

    @RequestMapping(value = ["/cache/deep/coveragezone"])
    @ResponseBody
    fun hashCoverageZoneDeepCache(
        @RequestParam(name = "ip") ip: String?,
        @RequestParam(name = ConsistentHashController.Companion.DELIVERY_SERVICE_ID) deliveryServiceId: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<*>? {
        val cache = trafficRouterManager.getTrafficRouter()
            .consistentHashForCoverageZone(ip, deliveryServiceId, requestPath, true)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}")
        return ResponseEntity.ok(cache)
    }

    @RequestMapping(value = ["/cache/geolocation"])
    @ResponseBody
    fun hashGeolocatedCache(
        @RequestParam(name = "ip") ip: String?,
        @RequestParam(name = ConsistentHashController.Companion.DELIVERY_SERVICE_ID) deliveryServiceId: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<*>? {
        val cache =
            trafficRouterManager.getTrafficRouter().consistentHashForGeolocation(ip, deliveryServiceId, requestPath)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}")
        return ResponseEntity.ok(cache)
    }

    @RequestMapping(value = ["/deliveryservice"])
    @ResponseBody
    fun hashDeliveryService(
        @RequestParam(name = ConsistentHashController.Companion.DELIVERY_SERVICE_ID) deliveryServiceId: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<*>? {
        val deliveryService =
            trafficRouterManager.getTrafficRouter().consistentHashDeliveryService(deliveryServiceId, requestPath)
                ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}")
        return ResponseEntity.ok(deliveryService)
    }

    @RequestMapping(value = ["/patternbased/regex"])
    @ResponseBody
    fun testPatternBasedRegex(
        @RequestParam(name = "regex") regex: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<MutableMap<String?, String?>?>? {

        // limit length of requestPath to protect against evil regexes
        if (requestPath != null && requestPath.length > ConsistentHashController.Companion.MAX_REQUEST_PATH_LENGTH) {
            val map: MutableMap<String?, String?> = HashMap()
            map["Bad Input"] =
                "Request Path length is restricted by API to " + ConsistentHashController.Companion.MAX_REQUEST_PATH_LENGTH + " characters"
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(map)
        }
        val pathToHash = trafficRouterManager.getTrafficRouter().buildPatternBasedHashString(regex, requestPath)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null)
        val map: MutableMap<String?, String?> = HashMap()
        map[ConsistentHashController.Companion.REQUEST_PATH] = requestPath
        map[ConsistentHashController.Companion.CONSISTENT_HASH_REGEX] = regex
        map[ConsistentHashController.Companion.RESULTING_PATH_TO_HASH] = pathToHash
        return ResponseEntity.ok(map)
    }

    @RequestMapping(value = ["/patternbased/deliveryservice"])
    @ResponseBody
    fun testPatternBasedDeliveryService(
        @RequestParam(name = ConsistentHashController.Companion.DELIVERY_SERVICE_ID) deliveryServiceId: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<MutableMap<String?, String?>?>? {
        val pathToHash = trafficRouterManager.getTrafficRouter()
            .buildPatternBasedHashStringDeliveryService(deliveryServiceId, requestPath)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null)
        val map: MutableMap<String?, String?> = HashMap()
        map[ConsistentHashController.Companion.REQUEST_PATH] = requestPath
        map[ConsistentHashController.Companion.DELIVERY_SERVICE_ID] = deliveryServiceId
        map[ConsistentHashController.Companion.RESULTING_PATH_TO_HASH] = pathToHash
        return ResponseEntity.ok(map)
    }

    @RequestMapping(value = ["/cache/coveragezone/steering"])
    @ResponseBody
    fun hashSteeringCoverageZoneCache(
        @RequestParam(name = "ip") ip: String?,
        @RequestParam(name = ConsistentHashController.Companion.DELIVERY_SERVICE_ID) deliveryServiceId: String?,
        @RequestParam(name = ConsistentHashController.Companion.REQUEST_PATH) requestPath: String?
    ): ResponseEntity<*>? {
        val cache = trafficRouterManager.getTrafficRouter()
            .consistentHashSteeringForCoverageZone(ip, deliveryServiceId, requestPath)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("{}")
        return ResponseEntity.ok(cache)
    }

    companion object {
        const val MAX_REQUEST_PATH_LENGTH = 28
        val RESULTING_PATH_TO_HASH: String? = "resultingPathToConsistentHash"
        val REQUEST_PATH: String? = "requestPath"
        val CONSISTENT_HASH_REGEX: String? = "consistentHashRegex"
        val DELIVERY_SERVICE_ID: String? = "deliveryServiceId"
    }
}