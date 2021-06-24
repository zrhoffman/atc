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

import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.LanguidState
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import java.net.InetAddress
import java.net.UnknownHostException

class LanguidState {
    private var ready = false
    private var trafficRouterManager: TrafficRouterManager? = null
    private var port = 0
    private var apiPort = 0
    private var securePort = 0
    private var secureApiPort = 0
    fun init() {
        if (trafficRouterManager == null || trafficRouterManager.getTrafficRouter() == null) {
            return
        }
        val tr = trafficRouterManager.getTrafficRouter()
        if (tr.cacheRegister == null) {
            return
        }
        val hostname: String
        hostname = try {
            InetAddress.getLocalHost().hostName.replace("\\..*".toRegex(), "")
        } catch (e: UnknownHostException) {
            LanguidState.Companion.LOGGER.error("Cannot lookup hostname of this traffic router!: " + e.message)
            return
        }
        val routers = tr.cacheRegister.trafficRouters
        val keyIter = routers.fieldNames()
        while (keyIter.hasNext()) {
            val key = keyIter.next()
            val routerJson = routers[key]
            if (!hostname.equals(key, ignoreCase = true)) {
                continue
            }
            initPorts(routerJson)
            break
        }
        setReady(true)
    }

    private fun initPorts(routerJson: JsonNode?) {
        if (routerJson.has("port")) {
            setPort(routerJson.get("port").asInt())
        }
        if (routerJson.has("api.port")) {
            setApiPort(routerJson.get("api.port").asInt())
            trafficRouterManager.setApiPort(apiPort)
        }
        if (routerJson.has("secure.port")) {
            setSecurePort(routerJson.get("secure.port").asInt())
        }
        if (routerJson.has("secure.api.port")) {
            setSecureApiPort(routerJson.get("secure.api.port").asInt())
            trafficRouterManager.setSecureApiPort(secureApiPort)
        }
    }

    fun isReady(): Boolean {
        return ready
    }

    fun setReady(ready: Boolean) {
        this.ready = ready
    }

    fun getPort(): Int {
        return port
    }

    fun setPort(port: Int) {
        this.port = port
    }

    fun getApiPort(): Int {
        return apiPort
    }

    fun setApiPort(apiPort: Int) {
        this.apiPort = apiPort
    }

    fun getTrafficRouterManager(): TrafficRouterManager? {
        return trafficRouterManager
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun getSecurePort(): Int {
        return securePort
    }

    fun setSecurePort(securePort: Int) {
        this.securePort = securePort
    }

    fun getSecureApiPort(): Int {
        return secureApiPort
    }

    fun setSecureApiPort(secureApiPort: Int) {
        this.secureApiPort = secureApiPort
    }

    companion object {
        private val LOGGER = Logger.getLogger(LanguidState::class.java)
    }
}