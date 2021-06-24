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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule.PostalsType

class RegionalGeoResult {
    enum class RegionalGeoResultType {
        ALLOWED, ALTERNATE_WITH_CACHE, ALTERNATE_WITHOUT_CACHE, DENIED
    }

    private var url: String? = null
    private var httpResponseCode = 0
    private var resultType: RegionalGeoResultType? = null
    private var ruleType: PostalsType? = null
    private var postal: String? = null
    private var usingFallbackConfig = false
    private var allowedByWhiteList = false
    fun getUrl(): String? {
        return url
    }

    fun setUrl(url: String?) {
        this.url = url
    }

    fun getHttpResponseCode(): Int {
        return httpResponseCode
    }

    fun setHttpResponseCode(rc: Int) {
        httpResponseCode = rc
    }

    fun getType(): RegionalGeoResultType? {
        return resultType
    }

    fun setType(resultType: RegionalGeoResultType?) {
        this.resultType = resultType
    }

    fun getRuleType(): PostalsType? {
        return ruleType
    }

    fun setRuleType(ruleType: PostalsType?) {
        this.ruleType = ruleType
    }

    fun getPostal(): String? {
        return postal
    }

    fun setPostal(postal: String?) {
        this.postal = postal
    }

    fun setUsingFallbackConfig(usingFallbackConfig: Boolean) {
        this.usingFallbackConfig = usingFallbackConfig
    }

    fun setAllowedByWhiteList(allowedByWhiteList: Boolean) {
        this.allowedByWhiteList = allowedByWhiteList
    }

    override fun toString(): String {
        val sb = StringBuilder()
        if (postal == null) {
            sb.append('-')
        } else {
            sb.append(postal)
        }
        sb.append(':')

        // allow:1; disallow:0
        if (resultType == RegionalGeoResultType.ALLOWED) {
            sb.append('1')
        } else {
            sb.append('0')
        }
        sb.append(':')

        // include rule: I, exclude rule: X, no rule matches: -
        if (resultType == RegionalGeoResultType.DENIED) {
            sb.append('-')
        } else {
            if (ruleType == null) {
                sb.append('-')
            } else if (ruleType == PostalsType.INCLUDE) {
                sb.append('I')
            } else {
                sb.append('X')
            }
        }
        sb.append(':')
        if (usingFallbackConfig) {
            sb.append('1')
        } else {
            sb.append('0')
        }
        sb.append(':')
        if (allowedByWhiteList) {
            sb.append('1')
        } else {
            sb.append('0')
        }
        return sb.toString()
    }

    companion object {
        const val REGIONAL_GEO_DENIED_HTTP_CODE = 520
    }
}