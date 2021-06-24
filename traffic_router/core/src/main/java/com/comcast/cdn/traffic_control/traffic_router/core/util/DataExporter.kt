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

import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Location
import com.comcast.cdn.traffic_control.traffic_router.core.edge.PropertiesAndCaches
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.status.model.CacheModel
import com.comcast.cdn.traffic_control.traffic_router.core.util.DataExporter
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import com.google.common.cache.CacheStats
import org.apache.log4j.Logger
import java.io.IOException
import java.util.Collections
import java.util.Properties

class DataExporter {
    private var trafficRouterManager: TrafficRouterManager? = null
    private var statTracker: StatTracker? = null
    private var federationExporter: FederationExporter? = null
    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun setStatTracker(statTracker: StatTracker?) {
        this.statTracker = statTracker
    }

    fun getStatTracker(): StatTracker? {
        return statTracker
    }

    fun getAppInfo(): MutableMap<String?, String?>? {
        val globals: MutableMap<String?, String?> = HashMap()
        System.getProperties().keys()
        val props = Properties()
        try {
            javaClass.getResourceAsStream("/version.prop").use { stream -> props.load(stream) }
        } catch (e: IOException) {
            DataExporter.Companion.LOGGER.warn(e, e)
        }
        for (key in props.keys) {
            globals[key as String] = props.getProperty(key as String)
        }
        return globals
    }

    fun getCachesByIp(ip: String?, geolocationProvider: String?): MutableMap<String?, Any?>? {
        val map: MutableMap<String?, Any?> = HashMap()
        map["requestIp"] = ip
        val cl = getLocationFromCzm(ip)
        if (cl != null) {
            map["locationByCoverageZone"] = cl.properties
        } else {
            map["locationByCoverageZone"] = DataExporter.Companion.NOT_FOUND_MESSAGE
        }
        try {
            val gl = trafficRouterManager.getTrafficRouter().getLocation(ip, geolocationProvider, "")
            if (gl != null) {
                map["locationByGeo"] = gl.properties
            } else {
                map["locationByGeo"] = DataExporter.Companion.NOT_FOUND_MESSAGE
            }
        } catch (e: GeolocationException) {
            DataExporter.Companion.LOGGER.warn(e, e)
            map["locationByGeo"] = e.toString()
        }
        try {
            val cidrAddress: CidrAddress = CidrAddress.Companion.fromString(ip)
            val federationsList = federationExporter.getMatchingFederations(cidrAddress)
            if (federationsList.isEmpty()) {
                map["locationByFederation"] = DataExporter.Companion.NOT_FOUND_MESSAGE
            } else {
                map["locationByFederation"] = federationsList
            }
        } catch (e: NetworkNodeException) {
            map["locationByFederation"] = DataExporter.Companion.NOT_FOUND_MESSAGE
        }
        val clFromDCZ = trafficRouterManager.getTrafficRouter().getDeepCoverageZoneLocationByIP(ip)
        if (clFromDCZ != null) {
            map["locationByDeepCoverageZone"] = PropertiesAndCaches(clFromDCZ)
        } else {
            map["locationByDeepCoverageZone"] = DataExporter.Companion.NOT_FOUND_MESSAGE
        }
        return map
    }

    private fun getLocationFromCzm(ip: String?): Location? {
        var nn: NetworkNode? = null
        try {
            nn = NetworkNode.Companion.getInstance().getNetwork(ip)
        } catch (e: NetworkNodeException) {
            DataExporter.Companion.LOGGER.warn(e)
        }
        if (nn == null) {
            return null
        }
        val locId = nn.loc
        val cl = nn.location
        if (cl != null) {
            return cl
        }
        if (locId != null) {
            // find CacheLocation
            val trafficRouter = trafficRouterManager.getTrafficRouter()
            val caches: MutableCollection<CacheLocation?>? = trafficRouter.cacheRegister.cacheLocations
            for (cl2 in caches) {
                if (cl2.getId() == locId) {
                    return cl2
                }
            }
        }
        return null
    }

    fun getLocations(): MutableList<String?>? {
        val models: MutableList<String?> = ArrayList()
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        for (location in trafficRouter.cacheRegister.cacheLocations) {
            models.add(location.id)
        }
        Collections.sort(models)
        return models
    }

    fun getCaches(locationId: String?): MutableList<CacheModel?>? {
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        val location = trafficRouter.cacheRegister.getCacheLocation(locationId)
        return getCaches(location)
    }

    fun getCaches(): MutableMap<String?, Any?>? {
        val models: MutableMap<String?, Any?> = HashMap()
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        for (location in trafficRouter.cacheRegister.cacheLocations) {
            models[location.id] = getCaches(location.id)
        }
        return models
    }

    private fun getCaches(location: CacheLocation?): MutableList<CacheModel?>? {
        val models: MutableList<CacheModel?> = ArrayList()
        for (cache in location.getCaches()) {
            val model = CacheModel()
            val ipAddresses: MutableList<String?> = ArrayList()
            val ips = cache.getIpAddresses(null)
            if (ips != null) {
                for (address in ips) {
                    ipAddresses.add(address.address.hostAddress)
                }
            }
            model.cacheId = cache.id
            model.fqdn = cache.fqdn
            model.ipAddresses = ipAddresses
            if (cache.hasAuthority()) {
                model.isCacheOnline = cache.isAvailable
            } else {
                model.isCacheOnline = false
            }
            models.add(model)
        }
        return models
    }

    fun getCacheControlMaxAge(): Int {
        var maxAge = 0
        if (trafficRouterManager != null) {
            val trafficRouter = trafficRouterManager.getTrafficRouter()
            if (trafficRouter != null) {
                val cacheRegister = trafficRouter.cacheRegister
                val config = cacheRegister.config
                if (config != null) {
                    maxAge = optInt(config, "api.cache-control.max-age")
                }
            }
        }
        return maxAge
    }

    fun getStaticZoneCacheStats(): MutableMap<String?, Any?>? {
        return createCacheStatsMap(trafficRouterManager.getTrafficRouter().zoneManager.staticCacheStats)
    }

    fun getDynamicZoneCacheStats(): MutableMap<String?, Any?>? {
        return createCacheStatsMap(trafficRouterManager.getTrafficRouter().zoneManager.dynamicCacheStats)
    }

    private fun createCacheStatsMap(cacheStats: CacheStats?): MutableMap<String?, Any?>? {
        val cacheStatsMap: MutableMap<String?, Any?> = HashMap()
        cacheStatsMap["requestCount"] = cacheStats.requestCount()
        cacheStatsMap["hitCount"] = cacheStats.hitCount()
        cacheStatsMap["missCount"] = cacheStats.missCount()
        cacheStatsMap["hitRate"] = cacheStats.hitRate()
        cacheStatsMap["missRate"] = cacheStats.missRate()
        cacheStatsMap["evictionCount"] = cacheStats.evictionCount()
        cacheStatsMap["loadCount"] = cacheStats.loadCount()
        cacheStatsMap["loadSuccessCount"] = cacheStats.loadSuccessCount()
        cacheStatsMap["loadExceptionCount"] = cacheStats.loadExceptionCount()
        cacheStatsMap["loadExceptionRate"] = cacheStats.loadExceptionRate()
        cacheStatsMap["totalLoadTime"] = cacheStats.totalLoadTime()
        cacheStatsMap["averageLoadPenalty"] = cacheStats.averageLoadPenalty()
        return cacheStatsMap
    }

    fun setFederationExporter(federationExporter: FederationExporter?) {
        this.federationExporter = federationExporter
    }

    companion object {
        private val LOGGER = Logger.getLogger(DataExporter::class.java)
        private val NOT_FOUND_MESSAGE: String? = "not found"
    }
}