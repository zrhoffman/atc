/*
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
package com.comcast.cdn.traffic_control.traffic_router.core.loc

import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIp
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
import com.comcast.cdn.traffic_control.traffic_router.core.router.HTTPRouteResult
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.common.net.InetAddresses
import org.apache.log4j.Logger
import java.io.File
import java.net.MalformedURLException
import java.net.URL

class AnonymousIp private constructor() {
    // Feature flipper
    // This is set to true if the CRConfig parameters containing the MMDB URL
    // and the config url are present AND any delivery service has the feature
    // enabled
    var enabled = false
    private val blockAnonymousIp = true
    private val blockHostingProvider = true
    private val blockPublicProxy = true
    private val blockTorExitNode = true
    private val ipv4Whitelist: AnonymousIpWhitelist? = null
    private val ipv6Whitelist: AnonymousIpWhitelist? = null
    private val redirectUrl: String? = null

    /*
	 * Returns the list of subnets in the IPv4 whitelist
	 */
    fun getIPv4Whitelist(): AnonymousIpWhitelist? {
        return ipv4Whitelist
    }

    /*
	 * Returns the list of subnets in the IPv6 whitelist
	 */
    fun getIPv6Whitelist(): AnonymousIpWhitelist? {
        return ipv6Whitelist
    }

    companion object {
        private val LOGGER = Logger.getLogger(AnonymousIp::class.java)
        private val currentConfig: AnonymousIp? = AnonymousIp()
        const val BLOCK_CODE = 403
        val WHITE_LIST_LOC: String? = "w"

        /*
	 * Returns the current anonymous ip object
	 */
        fun getCurrentConfig(): AnonymousIp? {
            return AnonymousIp.Companion.currentConfig
        }

        @Throws(JsonUtilsException::class)
        private fun parseIPv4Whitelist(config: JsonNode?, anonymousIp: AnonymousIp?) {
            if (config.has("ip4Whitelist")) {
                try {
                    anonymousIp.ipv4Whitelist = AnonymousIpWhitelist()
                    anonymousIp.ipv4Whitelist.init(JsonUtils.getJsonNode(config, "ip4Whitelist"))
                } catch (e: NetworkNodeException) {
                    AnonymousIp.Companion.LOGGER.error("Anonymous Ip ERR: Network node err ", e)
                }
            }
        }

        @Throws(JsonUtilsException::class)
        private fun parseIPv6Whitelist(config: JsonNode?, anonymousIp: AnonymousIp?) {
            if (config.has("ip6Whitelist")) {
                try {
                    anonymousIp.ipv6Whitelist = AnonymousIpWhitelist()
                    anonymousIp.ipv6Whitelist.init(JsonUtils.getJsonNode(config, "ip6Whitelist"))
                } catch (e: NetworkNodeException) {
                    AnonymousIp.Companion.LOGGER.error("Anonymous Ip ERR: Network node err ", e)
                }
            }
        }

        private fun parseConfigJson(config: JsonNode?): AnonymousIp? {
            val anonymousIp = AnonymousIp()
            try {
                val blockingTypes = JsonUtils.getJsonNode(config, "anonymousIp")
                anonymousIp.blockAnonymousIp = JsonUtils.getBoolean(blockingTypes, "blockAnonymousVPN")
                anonymousIp.blockHostingProvider = JsonUtils.getBoolean(blockingTypes, "blockHostingProvider")
                anonymousIp.blockPublicProxy = JsonUtils.getBoolean(blockingTypes, "blockPublicProxy")
                anonymousIp.blockTorExitNode = JsonUtils.getBoolean(blockingTypes, "blockTorExitNode")
                anonymousIp.enabled = AnonymousIp.Companion.currentConfig.enabled
                AnonymousIp.Companion.parseIPv4Whitelist(config, anonymousIp)
                AnonymousIp.Companion.parseIPv6Whitelist(config, anonymousIp)
                if (config.has("redirectUrl")) {
                    anonymousIp.redirectUrl = JsonUtils.getString(config, "redirectUrl")
                }
                return anonymousIp
            } catch (e: Exception) {
                AnonymousIp.Companion.LOGGER.error("AnonymousIp ERR: parsing config file failed", e)
            }
            return null
        }

        fun parseConfigFile(f: File?, verifyOnly: Boolean): Boolean {
            var json: JsonNode? = null
            json = try {
                val mapper = ObjectMapper()
                mapper.readTree(f)
            } catch (e: Exception) {
                AnonymousIp.Companion.LOGGER.error("AnonymousIp ERR: json file exception $f", e)
                return false
            }
            val anonymousIp: AnonymousIp = AnonymousIp.Companion.parseConfigJson(json) ?: return false
            if (!verifyOnly) {
                AnonymousIp.Companion.currentConfig = anonymousIp // point to the new parsed object
            }
            return true
        }

        private fun inWhitelist(address: String?): Boolean {
            // If the address is ipv4 check against the ipv4whitelist
            if (address.indexOf(':') == -1) {
                if (AnonymousIp.Companion.currentConfig.ipv4Whitelist.contains(address)) {
                    return true
                }
            } else {
                if (AnonymousIp.Companion.currentConfig.ipv6Whitelist.contains(address)) {
                    return true
                }
            }
            return false
        }

        fun enforce(trafficRouter: TrafficRouter?, dsvcId: String?, url: String?, ip: String?): Boolean {
            val address = InetAddresses.forString(ip)
            if (AnonymousIp.Companion.inWhitelist(ip)) {
                return false
            }
            val response = trafficRouter.getAnonymousIpDatabaseService().lookupIp(address) ?: return false

            // Check if the ip should be blocked by checking if the ip falls into a
            // specific policy
            if (AnonymousIp.Companion.getCurrentConfig().blockAnonymousIp && response.isAnonymousVpn) {
                return true
            }
            if (AnonymousIp.Companion.getCurrentConfig().blockHostingProvider && response.isHostingProvider) {
                return true
            }
            if (AnonymousIp.Companion.getCurrentConfig().blockPublicProxy && response.isPublicProxy) {
                return true
            }
            return if (AnonymousIp.Companion.getCurrentConfig().blockTorExitNode && response.isTorExitNode) {
                true
            } else false
        }

        @Throws(MalformedURLException::class)  /*
	 * Enforces the anonymous ip blocking policies
	 * 
	 * If the Delivery Service has anonymous ip blocking enabled And the ip is
	 * in the anonymous ip database The ip will be blocked if it matches a
	 * policy defined in the config file
	 */   fun enforce(
            trafficRouter: TrafficRouter?, request: Request?, deliveryService: DeliveryService?, cache: Cache?,
            routeResult: HTTPRouteResult?, track: StatTracker.Track?
        ) {
            val httpRequest = HTTPRequest::class.java.cast(request)

            // If the database isn't initialized dont block
            if (!trafficRouter.getAnonymousIpDatabaseService().isInitialized) {
                return
            }

            // Check if the ip is allowed
            val block: Boolean = AnonymousIp.Companion.enforce(
                trafficRouter,
                deliveryService.getId(),
                httpRequest.requestedUrl,
                httpRequest.clientIP
            )

            // Block the ip if it is not allowed
            if (block) {
                routeResult.setResponseCode(AnonymousIp.Companion.BLOCK_CODE)
                track.setResult(ResultType.ANON_BLOCK)
                if (AnonymousIp.Companion.getCurrentConfig().redirectUrl != null) {
                    routeResult.addUrl(URL(AnonymousIp.Companion.getCurrentConfig().redirectUrl))
                }
            }
        }
    }

    init {
        try {
            ipv4Whitelist = AnonymousIpWhitelist()
            ipv6Whitelist = AnonymousIpWhitelist()
        } catch (e: NetworkNodeException) {
            AnonymousIp.Companion.LOGGER.error("AnonymousIp ERR: Network node exception ", e)
        }
    }
}