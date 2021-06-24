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
package com.comcast.cdn.traffic_control.traffic_router.core.loc

import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode.SuperNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeo
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult.RegionalGeoResultType
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule.PostalsType
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
import com.comcast.cdn.traffic_control.traffic_router.core.router.HTTPRouteResult
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.io.File
import java.net.MalformedURLException
import java.net.URL
import java.util.regex.Pattern

class RegionalGeo private constructor() {
    private var fallback = false
    private val regionalGeoDsvcs: MutableMap<String?, RegionalGeoDsvc?>? = HashMap()
    fun setFallback(fallback: Boolean) {
        this.fallback = fallback
    }

    fun isFallback(): Boolean {
        return fallback
    }

    private fun matchRule(dsvcId: String?, url: String?): RegionalGeoRule? {
        val regionalGeoDsvc = regionalGeoDsvcs.get(dsvcId)
        if (regionalGeoDsvc == null) {
            LOGGER.debug("RegionalGeo: dsvc not found: $dsvcId")
            return null
        }
        val rule = regionalGeoDsvc.matchRule(url)
        if (rule == null) {
            LOGGER.debug(
                "RegionalGeo: no rule match for dsvc "
                        + dsvcId + " with url " + url
            )
            return null
        }
        return rule
    }

    private fun addRule(
        dsvcId: String?,
        urlRegex: String?,
        postalsType: PostalsType?,
        postals: MutableSet<String?>?,
        networkRoot: NetworkNode?,
        alternateUrl: String?,
        isSteeringDS: Boolean,
        coordinateRanges: MutableList<RegionalGeoCoordinateRange?>?
    ): Boolean {

        // Loop check for alternateUrl with fqdn against the regex before adding
        val urlRegexPattern: Pattern?
        urlRegexPattern = try {
            LOGGER.info("RegionalGeo: compile regex for url $urlRegex")
            Pattern.compile(urlRegex, Pattern.CASE_INSENSITIVE)
        } catch (e: Exception) {
            LOGGER.error("RegionalGeo ERR: Pattern.compile exception", e)
            return false
        }
        if ((alternateUrl.toLowerCase().startsWith(HTTP_SCHEME) || alternateUrl.toLowerCase().startsWith(HTTPS_SCHEME))
            && urlRegexPattern.matcher(alternateUrl).matches()
        ) {
            LOGGER.error(
                "RegionalGeo ERR: possible LOOP detected, alternate fqdn url " + alternateUrl
                        + " matches regex " + urlRegex + " in dsvc " + dsvcId
            )
            return false
        }
        if (isSteeringDS && !(alternateUrl.toLowerCase().startsWith(HTTP_SCHEME) || alternateUrl.toLowerCase()
                .startsWith(
                    HTTPS_SCHEME
                ))
        ) {
            LOGGER.error(
                "RegionalGeo ERR: Alternate URL for Steering delivery service: "
                        + dsvcId + " must start with " + HTTP_SCHEME + " or " + HTTPS_SCHEME
            )
            return false
        }
        var regionalGeoDsvc = regionalGeoDsvcs.get(dsvcId)
        if (regionalGeoDsvc == null) {
            regionalGeoDsvc = RegionalGeoDsvc(dsvcId)
            regionalGeoDsvcs[dsvcId] = regionalGeoDsvc
        }
        val urlRule = RegionalGeoRule(
            regionalGeoDsvc,
            urlRegex, urlRegexPattern,
            postalsType, postals,
            networkRoot, alternateUrl, coordinateRanges
        )
        LOGGER.info("RegionalGeo: adding $urlRule")
        regionalGeoDsvc.addRule(urlRule)
        return true
    }

    companion object {
        private val LOGGER = Logger.getLogger(RegionalGeo::class.java)
        val HTTP_SCHEME: String? = "http://"
        val HTTPS_SCHEME: String? = "https://"
        private var currentConfig: RegionalGeo? = RegionalGeo()

        /// static methods
        @Throws(NetworkNodeException::class)
        private fun parseWhiteListJson(json: JsonNode?): NetworkNode? {
            val root = SuperNode()
            for (subnetNode in json) {
                val subnet = subnetNode.asText()
                val node = NetworkNode(subnet, RegionalGeoRule.Companion.WHITE_LIST_NODE_LOCATION)
                if (subnet.indexOf(':') == -1) { // ipv4 or ipv6
                    root.add(node)
                } else {
                    root.add6(node)
                }
            }
            return root
        }

        private fun checkCoordinateRangeValidity(cr: RegionalGeoCoordinateRange?): Boolean {
            if (cr.getMinLat() < -90.0 || cr.getMinLat() > 90.0 ||
                cr.getMaxLat() < -90.0 || cr.getMaxLat() > 90.0 ||
                cr.getMinLon() < -180.0 || cr.getMinLon() > 180.0 ||
                cr.getMaxLon() < -180.0 || cr.getMaxLon() > 180.0
            ) {
                LOGGER.error("The supplied coordinate range is invalid. Latitude must be between -90.0 and +90.0, Longitude must be between -180.0 and +180.0.")
                return false
            }
            return true
        }

        private fun parseLocationJsonCoordinateRange(locationJson: JsonNode?): MutableList<RegionalGeoCoordinateRange?>? {
            val coordinateRange: MutableList<RegionalGeoCoordinateRange?> = ArrayList()
            val coordinateRangeJson = locationJson.get("coordinateRange") ?: return null
            val mapper = ObjectMapper()
            var cr: RegionalGeoCoordinateRange? = RegionalGeoCoordinateRange()
            for (cRange in coordinateRangeJson) {
                cr = mapper.convertValue(cRange, RegionalGeoCoordinateRange::class.java)
                if (checkCoordinateRangeValidity(cr)) {
                    coordinateRange.add(cr)
                }
            }
            return coordinateRange
        }

        private fun parseLocationJson(
            locationJson: JsonNode?,
            postals: MutableSet<String?>?
        ): PostalsType? {
            var postalsType = PostalsType.UNDEFINED
            var postalsJson = locationJson.get("includePostalCode")
            if (postalsJson != null) {
                postalsType = PostalsType.INCLUDE
            } else {
                postalsJson = locationJson.get("excludePostalCode")
                if (postalsJson == null) {
                    LOGGER.error("RegionalGeo ERR: no include/exclude in geolocation")
                    return PostalsType.UNDEFINED
                }
                postalsType = PostalsType.EXCLUDE
            }
            for (postal in postalsJson) {
                postals.add(postal.asText())
            }
            return postalsType
        }

        private fun parseConfigJson(json: JsonNode?): RegionalGeo? {
            val regionalGeo = RegionalGeo()
            regionalGeo.setFallback(true)
            try {
                val dsvcsJson = JsonUtils.getJsonNode(json, "deliveryServices")
                LOGGER.info("RegionalGeo: parse json with rule count " + dsvcsJson.size())
                for (ruleJson in dsvcsJson) {
                    val dsvcId = JsonUtils.getString(ruleJson, "deliveryServiceId")
                    if (dsvcId.trim { it <= ' ' }.isEmpty()) {
                        LOGGER.error("RegionalGeo ERR: deliveryServiceId empty")
                        return null
                    }
                    var isSteeringDS = false
                    try {
                        isSteeringDS = JsonUtils.getBoolean(ruleJson, "isSteeringDS")
                    } catch (e: JsonUtilsException) {
                        //It's not in the config so we can just keep it set as false.
                        LOGGER.debug("RegionalGeo ERR: isSteeringDS empty")
                    }
                    val urlRegex = JsonUtils.getString(ruleJson, "urlRegex")
                    if (urlRegex.trim { it <= ' ' }.isEmpty()) {
                        LOGGER.error("RegionalGeo ERR: urlRegex empty")
                        return null
                    }
                    val redirectUrl = JsonUtils.getString(ruleJson, "redirectUrl")
                    if (redirectUrl.trim { it <= ' ' }.isEmpty()) {
                        LOGGER.error("RegionalGeo ERR: redirectUrl empty")
                        return null
                    }

                    // FSAs (postal codes)
                    val locationJson = JsonUtils.getJsonNode(ruleJson, "geoLocation")
                    val postals: MutableSet<String?> = HashSet()
                    val postalsType = parseLocationJson(locationJson, postals)
                    if (postalsType == PostalsType.UNDEFINED) {
                        LOGGER.error("RegionalGeo ERR: geoLocation empty")
                        return null
                    }
                    // coordinate range
                    val coordinateRanges = parseLocationJsonCoordinateRange(locationJson)

                    // white list
                    var whiteListRoot: NetworkNode? = null
                    val whiteListJson = ruleJson["ipWhiteList"]
                    if (whiteListJson != null) {
                        whiteListRoot = parseWhiteListJson(whiteListJson)
                    }


                    // add the rule
                    if (!regionalGeo.addRule(
                            dsvcId,
                            urlRegex,
                            postalsType,
                            postals,
                            whiteListRoot,
                            redirectUrl,
                            isSteeringDS,
                            coordinateRanges
                        )
                    ) {
                        LOGGER.error("RegionalGeo ERR: add rule failed on parsing json file")
                        return null
                    }
                }
                regionalGeo.setFallback(false)
                return regionalGeo
            } catch (e: Exception) {
                LOGGER.error("RegionalGeo ERR: parse json file with exception", e)
            }
            return null
        }

        fun parseConfigFile(f: File?, verifyOnly: Boolean): Boolean {
            val mapper = ObjectMapper()
            var json: JsonNode? = null
            json = try {
                mapper.readTree(f)
            } catch (e: Exception) {
                LOGGER.error("RegionalGeo ERR: json file exception $f", e)
                currentConfig.setFallback(true)
                return false
            }
            val regionalGeo = parseConfigJson(json)
            if (regionalGeo == null) {
                currentConfig.setFallback(true)
                return false
            }
            if (!verifyOnly) {
                currentConfig = regionalGeo // point to the new parsed object
            }
            currentConfig.setFallback(false)
            LOGGER.debug("RegionalGeo: create instance from new json")
            return true
        }

        fun enforce(
            dsvcId: String?, url: String?,
            ip: String?, postalCode: String?, lat: Double, lon: Double
        ): RegionalGeoResult? {
            val result = RegionalGeoResult()
            var allowed = false
            var rule: RegionalGeoRule? = null
            result.postal = postalCode
            result.setUsingFallbackConfig(currentConfig.isFallback())
            result.setAllowedByWhiteList(false)
            rule = currentConfig.matchRule(dsvcId, url)
            if (rule == null) {
                result.httpResponseCode = RegionalGeoResult.Companion.REGIONAL_GEO_DENIED_HTTP_CODE
                result.type = RegionalGeoResultType.DENIED
                LOGGER.debug(
                    "RegionalGeo: denied for dsvc " + dsvcId
                            + ", url " + url + ", postal " + postalCode
                )
                return result
            }

            // first match whitelist, then FSA (postal)
            if (rule.isIpInWhiteList(ip)) {
                LOGGER.debug("RegionalGeo: allowing ip in whitelist")
                allowed = true
                result.setAllowedByWhiteList(true)
            } else {
                allowed = if (postalCode == null || postalCode.isEmpty()) {
                    LOGGER.warn("RegionalGeo: alternate a request with null or empty postal")
                    rule.isAllowedCoordinates(lat, lon)
                } else {
                    rule.isAllowedPostal(postalCode)
                }
            }
            val alternateUrl = rule.alternateUrl
            result.ruleType = rule.postalsType
            if (allowed) {
                result.url = url
                result.type = RegionalGeoResultType.ALLOWED
            } else {
                // For a disallowed client, if alternateUrl starts with "http://" or "https://"
                // just redirect the client to this url without any cache selection;
                // if alternateUrl only has path and file name like "/path/abc.html",
                // then cache selection process will be needed, and hostname will be
                // added to make it like "http://cache01.example.com/path/abc.html" later.
                if (alternateUrl.toLowerCase().startsWith(HTTP_SCHEME) || alternateUrl.toLowerCase()
                        .startsWith(HTTPS_SCHEME)
                ) {
                    result.url = alternateUrl
                    result.type = RegionalGeoResultType.ALTERNATE_WITHOUT_CACHE
                } else {
                    val redirectUrl: String?
                    redirectUrl = if (alternateUrl.startsWith("/")) { // add a '/' prefix if necessary for url path
                        alternateUrl
                    } else {
                        "/$alternateUrl"
                    }
                    LOGGER.debug("RegionalGeo: alternate with cache url $redirectUrl")
                    result.url = redirectUrl
                    result.type = RegionalGeoResultType.ALTERNATE_WITH_CACHE
                }
            }
            LOGGER.debug("RegionalGeo: result $result for dsvc $dsvcId, url $url, ip $ip")
            return result
        }

        @JvmOverloads
        @Throws(MalformedURLException::class)
        fun enforce(
            trafficRouter: TrafficRouter?, request: Request?,
            deliveryService: DeliveryService?, cache: Cache?,
            routeResult: HTTPRouteResult?, track: StatTracker.Track?, isSteering: Boolean = false
        ) {
            LOGGER.debug("RegionalGeo: enforcing")
            var clientGeolocation: Geolocation? = null
            try {
                clientGeolocation = trafficRouter.getClientGeolocation(request.getClientIP(), track, deliveryService)
            } catch (e: GeolocationException) {
                LOGGER.warn("RegionalGeo: failed looking up Client GeoLocation: " + e.message)
            }
            var postalCode: String? = null
            var lat = 0.0
            var lon = 0.0
            if (clientGeolocation != null) {
                postalCode = clientGeolocation.postalCode

                // Get the first 3 chars in the postal code. These 3 chars are called FSA in Canadian postal codes.
                if (postalCode != null && postalCode.length > 3) {
                    postalCode = postalCode.substring(0, 3)
                } else {
                    lat = clientGeolocation.latitude
                    lon = clientGeolocation.longitude
                }
            }
            val httpRequest = HTTPRequest::class.java.cast(request)
            val result = enforce(
                deliveryService.getId(), httpRequest.requestedUrl,
                httpRequest.clientIP, postalCode, lat, lon
            )
            if (cache == null && result.getType() == RegionalGeoResultType.ALTERNATE_WITH_CACHE) {
                LOGGER.debug("RegionalGeo: denied for dsvc " + deliveryService.getId() + ", url " + httpRequest.requestedUrl + ", postal " + postalCode + ". Relative re-direct URLs not allowed for Multi Route Delivery Services.")
                result.setHttpResponseCode(RegionalGeoResult.Companion.REGIONAL_GEO_DENIED_HTTP_CODE)
                result.setType(RegionalGeoResultType.DENIED)
            }
            if (cache == null && result.getType() == RegionalGeoResultType.ALLOWED) {
                LOGGER.debug("RegionalGeo: Client is allowed to access steering service, returning null re-direct URL")
                result.setUrl(null)
                updateTrack(track, result)
                return
            }
            updateTrack(track, result)
            if (result.getType() == RegionalGeoResultType.DENIED) {
                routeResult.setResponseCode(result.getHttpResponseCode())
            } else {
                val redirectURIString = createRedirectURIString(httpRequest, deliveryService, cache, result)
                if ("Denied" != redirectURIString) {
                    routeResult.addUrl(URL(redirectURIString))
                } else {
                    LOGGER.warn("RegionalGeo: this needs a better error message, createRedirectURIString returned denied")
                }
            }
        }

        private fun updateTrack(track: StatTracker.Track?, regionalGeoResult: RegionalGeoResult?) {
            track.setRegionalGeoResult(regionalGeoResult)
            val resultType = regionalGeoResult.getType()
            if (resultType == RegionalGeoResultType.DENIED) {
                track.setResult(ResultType.RGDENY)
                track.setResultDetails(ResultDetails.REGIONAL_GEO_NO_RULE)
                return
            }
            if (resultType == RegionalGeoResultType.ALTERNATE_WITH_CACHE) {
                track.setResult(ResultType.RGALT)
                track.setResultDetails(ResultDetails.REGIONAL_GEO_ALTERNATE_WITH_CACHE)
                return
            }
            if (resultType == RegionalGeoResultType.ALTERNATE_WITHOUT_CACHE) {
                track.setResult(ResultType.RGALT)
                track.setResultDetails(ResultDetails.REGIONAL_GEO_ALTERNATE_WITHOUT_CACHE)
                return
            }

            // else ALLOWED, result & resultDetail shall be normal case, do not modify
        }

        private fun createRedirectURIString(
            request: HTTPRequest?, deliveryService: DeliveryService?,
            cache: Cache?, regionalGeoResult: RegionalGeoResult?
        ): String? {
            if (regionalGeoResult.getType() == RegionalGeoResultType.ALLOWED) {
                return deliveryService.createURIString(request, cache)
            }
            if (regionalGeoResult.getType() == RegionalGeoResultType.ALTERNATE_WITH_CACHE) {
                return deliveryService.createURIString(request, regionalGeoResult.getUrl(), cache)
            }
            return if (regionalGeoResult.getType() == RegionalGeoResultType.ALTERNATE_WITHOUT_CACHE) {
                regionalGeoResult.getUrl()
            } else "Denied"
            // DENIED
        }
    }
}