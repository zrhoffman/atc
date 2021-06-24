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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule
import org.apache.log4j.Logger
import java.util.regex.Pattern

class RegionalGeoRule(
    private val regionalGeoDsvc: RegionalGeoDsvc?,
    private val urlRegex: String?, private val pattern: Pattern?, private val postalsType: PostalsType?,
    private val postals: MutableSet<String?>?, private val whiteListRoot: NetworkNode?,
    // if disallowed, client will be redirected to this url
    private val alternateUrl: String?, private val coordinateRanges: MutableList<RegionalGeoCoordinateRange?>?
) {
    enum class PostalsType {
        EXCLUDE, INCLUDE, UNDEFINED
    }

    fun matchesUrl(url: String?): Boolean {
        return pattern.matcher(url).matches()
    }

    fun isAllowedPostal(postal: String?): Boolean {
        if (postalsType == PostalsType.INCLUDE) {
            if (postals.contains(postal)) {
                return true
            }
        } else { // EXCLUDE
            if (!postals.contains(postal)) {
                return true
            }
        }
        return false
    }

    fun isAllowedCoordinates(lat: Double, lon: Double): Boolean {
        if (coordinateRanges == null) {
            return false
        }
        for (i in coordinateRanges.indices) {
            val coordinateRange = coordinateRanges[i]
            if (lat >= coordinateRange.getMinLat() && lon >= coordinateRange.getMinLon() &&
                lat <= coordinateRange.getMaxLat() && lon <= coordinateRange.getMaxLon()
            ) {
                return true
            }
        }
        return false
    }

    fun isIpInWhiteList(ip: String?): Boolean {
        if (whiteListRoot == null) {
            return false
        }
        try {
            val nn = whiteListRoot.getNetwork(ip)
            if (nn.loc === RegionalGeoRule.Companion.WHITE_LIST_NODE_LOCATION) {
                return true
            }
        } catch (e: NetworkNodeException) {
            RegionalGeoRule.Companion.LOGGER.warn("RegionalGeo: exception", e)
        }
        return false
    }

    fun getUrlRegex(): String? {
        return urlRegex
    }

    fun getPattern(): Pattern? {
        return pattern
    }

    fun getPostalsType(): PostalsType? {
        return postalsType
    }

    fun getAlternateUrl(): String? {
        return alternateUrl
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("RULE: dsvc ")
        sb.append(regionalGeoDsvc.getId())
        sb.append(", regex ")
        sb.append(urlRegex)
        sb.append(", alternate ")
        sb.append(alternateUrl)
        sb.append(", type ")
        sb.append(postalsType)
        sb.append(", postals ")
        for (s in postals) {
            sb.append(s)
            sb.append(',')
        }
        return sb.toString()
    }

    companion object {
        private val LOGGER = Logger.getLogger(RegionalGeoRule::class.java)
        val WHITE_LIST_NODE_LOCATION: String? = "w"
    }
}