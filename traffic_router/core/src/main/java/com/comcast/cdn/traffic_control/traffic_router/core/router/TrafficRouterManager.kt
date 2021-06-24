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
package com.comcast.cdn.traffic_control.traffic_router.core.router

import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServer
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseService
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationService
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import java.io.IOException
import java.net.UnknownHostException
import java.util.concurrent.ConcurrentHashMap

class TrafficRouterManager : ApplicationListener<ContextRefreshedEvent?> {
    private var state: JsonNode? = null
    private var trafficRouter: TrafficRouter? = null
    private var geolocationService: GeolocationService? = null
    private var geolocationService6: GeolocationService? = null
    private var anonymousIpService: AnonymousIpDatabaseService? = null
    private var statTracker: StatTracker? = null
    private var nameServer: NameServer? = null
    private var trafficOpsUtils: TrafficOpsUtils? = null
    private var federationRegistry: FederationRegistry? = null
    private var steeringRegistry: SteeringRegistry? = null
    private var applicationContext: ApplicationContext? = null
    private var apiPort: Int = TrafficRouterManager.Companion.DEFAULT_API_PORT
    private var secureApiPort: Int = TrafficRouterManager.Companion.DEFAULT_SECURE_API_PORT
    fun getNameServer(): NameServer? {
        return nameServer
    }

    fun trackEvent(event: String?) {
        TrafficRouterManager.Companion.timeTracker.put(event, System.currentTimeMillis())
    }

    fun setNameServer(nameServer: NameServer?) {
        this.nameServer = nameServer
    }

    @Throws(UnknownHostException::class)
    fun setState(jsonObject: JsonNode?): Boolean {
        trackEvent("lastCacheStateCheck")
        if (jsonObject == null) {
            return false
        }
        trackEvent("lastCacheStateChange")
        synchronized(this) {
            state = jsonObject
            if (trafficRouter != null) {
                trafficRouter.setState(state)
            }
            return true
        }
    }

    fun getTrafficRouter(): TrafficRouter? {
        return trafficRouter
    }

    @Throws(IOException::class)
    fun setCacheRegister(cacheRegister: CacheRegister?) {
        trackEvent("lastConfigCheck")
        if (cacheRegister == null) {
            return
        }
        val tr = TrafficRouter(
            cacheRegister,
            geolocationService,
            geolocationService6,
            anonymousIpService,
            statTracker,
            trafficOpsUtils,
            federationRegistry,
            this
        )
        tr.setSteeringRegistry(steeringRegistry)
        synchronized(this) {
            if (state != null) {
                try {
                    tr.setState(state)
                } catch (e: UnknownHostException) {
                    TrafficRouterManager.Companion.LOGGER.warn(e, e)
                }
            }
            trafficRouter = tr
            if (applicationContext != null) {
                trafficRouter.setApplicationContext(applicationContext)
            }
        }
        trackEvent("lastConfigChange")
    }

    fun setGeolocationService(geolocationService: GeolocationService?) {
        this.geolocationService = geolocationService
    }

    fun setGeolocationService6(geolocationService: GeolocationService?) {
        geolocationService6 = geolocationService
    }

    fun setAnonymousIpService(anonymousIpService: AnonymousIpDatabaseService?) {
        this.anonymousIpService = anonymousIpService
    }

    fun setStatTracker(statTracker: StatTracker?) {
        this.statTracker = statTracker
    }

    fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    fun setFederationRegistry(federationRegistry: FederationRegistry?) {
        this.federationRegistry = federationRegistry
    }

    fun setSteeringRegistry(steeringRegistry: SteeringRegistry?) {
        this.steeringRegistry = steeringRegistry
    }

    override fun onApplicationEvent(event: ContextRefreshedEvent?) {
        applicationContext = event.getApplicationContext()
        if (trafficRouter != null) {
            trafficRouter.setApplicationContext(applicationContext)
            trafficRouter.configurationChanged()
        }
    }

    fun setApiPort(apiPort: Int) {
        this.apiPort = apiPort
    }

    fun getApiPort(): Int {
        return apiPort
    }

    fun getSecureApiPort(): Int {
        return secureApiPort
    }

    fun setSecureApiPort(secureApiPort: Int) {
        this.secureApiPort = secureApiPort
    }

    companion object {
        private val LOGGER = Logger.getLogger(TrafficRouterManager::class.java)
        const val DEFAULT_API_PORT = 3333
        const val DEFAULT_SECURE_API_PORT = 0 // Must be set through server.xml properties
        private val timeTracker: MutableMap<String?, Long?>? = ConcurrentHashMap()
        fun getTimeTracker(): MutableMap<String?, Long?>? {
            return TrafficRouterManager.Companion.timeTracker
        }
    }
}