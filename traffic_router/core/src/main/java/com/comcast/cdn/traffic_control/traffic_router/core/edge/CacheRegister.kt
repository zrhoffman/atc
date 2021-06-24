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
package com.comcast.cdn.traffic_control.traffic_router.core.edge

import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
import com.fasterxml.jackson.databind.JsonNode
import java.util.TreeSet
import java.util.stream.Collectors

class CacheRegister {
    private val configuredLocations: MutableMap<String?, CacheLocation?>?
    private val edgeTrafficRouterLocations: MutableMap<String?, TrafficRouterLocation?>?
    private var trafficRouters: JsonNode? = null
    private var allCaches: MutableMap<String?, Cache?>? = null
    private var deliveryServiceMatchers: TreeSet<DeliveryServiceMatcher?>? = null
    private var dsMap: MutableMap<String?, DeliveryService?>? = null
    private var config: JsonNode? = null
    private var stats: JsonNode? = null
    private var edgeTrafficRouterCount = 0
    fun getCacheLocation(id: String?): CacheLocation? {
        return configuredLocations.get(id)
    }

    fun getCacheLocations(): MutableSet<CacheLocation?>? {
        val result: MutableSet<CacheLocation?> = HashSet(configuredLocations.size)
        result.addAll(configuredLocations.values)
        return result
    }

    fun getCacheLocationById(id: String?): CacheLocation? {
        for (location in configuredLocations.values) {
            if (id == location.getId()) {
                return location
            }
        }
        return null
    }

    fun getEdgeTrafficRouterLocation(id: String?): TrafficRouterLocation? {
        return edgeTrafficRouterLocations.get(id)
    }

    fun getEdgeTrafficRouterLocations(): MutableList<TrafficRouterLocation?>? {
        return ArrayList(edgeTrafficRouterLocations.values)
    }

    private fun setEdgeTrafficRouterCount(count: Int) {
        edgeTrafficRouterCount = count
    }

    fun getEdgeTrafficRouterCount(): Int {
        return edgeTrafficRouterCount
    }

    fun getAllEdgeTrafficRouters(): MutableList<Node?>? {
        val edgeTrafficRouters: MutableList<Node?> = ArrayList()
        for (location in getEdgeTrafficRouterLocations()) {
            edgeTrafficRouters.addAll(location.getTrafficRouters())
        }
        return edgeTrafficRouters
    }

    /**
     * Sets the configured locations.
     *
     * @param locations
     * the new configured locations
     */
    fun setConfiguredLocations(locations: MutableSet<CacheLocation?>?) {
        configuredLocations.clear()
        for (newLoc in locations) {
            configuredLocations[newLoc.getId()] = newLoc
        }
    }

    fun setEdgeTrafficRouterLocations(locations: MutableCollection<TrafficRouterLocation?>?) {
        var count = 0
        edgeTrafficRouterLocations.clear()
        for (newLoc in locations) {
            edgeTrafficRouterLocations[newLoc.getId()] = newLoc
            val trafficRouters = newLoc.getTrafficRouters()
            if (trafficRouters != null) {
                count += trafficRouters.size
            }
        }
        setEdgeTrafficRouterCount(count)
    }

    fun hasEdgeTrafficRouters(): Boolean {
        return !edgeTrafficRouterLocations.isEmpty()
    }

    fun setCacheMap(map: MutableMap<String?, Cache?>?) {
        allCaches = map
    }

    fun getCacheMap(): MutableMap<String?, Cache?>? {
        return allCaches
    }

    fun getDeliveryServiceMatchers(deliveryService: DeliveryService?): MutableSet<DeliveryServiceMatcher?>? {
        return deliveryServiceMatchers.stream()
            .filter { deliveryServiceMatcher: DeliveryServiceMatcher? -> deliveryServiceMatcher.getDeliveryService().id == deliveryService.getId() }
            .collect(Collectors.toCollection { TreeSet() })
    }

    fun setDeliveryServiceMatchers(matchers: TreeSet<DeliveryServiceMatcher?>?) {
        deliveryServiceMatchers = matchers
    }

    /**
     * Gets the first [DeliveryService] that matches the [Request].
     *
     * @param request
     * the request to match
     * @return the DeliveryService that matches the request
     */
    fun getDeliveryService(request: Request?): DeliveryService? {
        if (deliveryServiceMatchers == null) {
            return null
        }
        for (m in deliveryServiceMatchers) {
            if (m.matches(request)) {
                return m.getDeliveryService()
            }
        }
        return null
    }

    fun getDeliveryService(deliveryServiceId: String?): DeliveryService? {
        return dsMap.get(deliveryServiceId)
    }

    fun filterAvailableCacheLocations(deliveryServiceId: String?): MutableList<CacheLocation?>? {
        val deliveryService = dsMap.get(deliveryServiceId) ?: return null
        return deliveryService.filterAvailableLocations(getCacheLocations())
    }

    fun setDeliveryServiceMap(dsMap: MutableMap<String?, DeliveryService?>?) {
        this.dsMap = dsMap
    }

    fun getTrafficRouters(): JsonNode? {
        return trafficRouters
    }

    fun setTrafficRouters(o: JsonNode?) {
        trafficRouters = o
    }

    fun setConfig(o: JsonNode?) {
        config = o
    }

    fun getConfig(): JsonNode? {
        return config
    }

    fun getDeliveryServices(): MutableMap<String?, DeliveryService?>? {
        return dsMap
    }

    fun getStats(): JsonNode? {
        return stats
    }

    fun setStats(stats: JsonNode?) {
        this.stats = stats
    }

    init {
        configuredLocations = HashMap()
        edgeTrafficRouterLocations = HashMap()
    }
}