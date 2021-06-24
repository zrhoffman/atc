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
package com.comcast.cdn.traffic_control.traffic_router.core.request

import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableStringByLength
import java.util.regex.Matcher
import java.util.regex.Pattern

class RequestMatcher @JvmOverloads constructor(
    type: DeliveryServiceMatcher.Type?,
    regex: String?,
    requestHeader: String? = ""
) : Comparable<RequestMatcher?> {
    private val type: DeliveryServiceMatcher.Type?
    private val pattern: Pattern?
    private val requestHeader: String? = ""
    private val comparableRegex: ComparableStringByLength?
    fun matches(request: Request?): Boolean {
        val target = getTarget(request) ?: return false
        return pattern.matcher(target).matches()
    }

    fun getType(): DeliveryServiceMatcher.Type? {
        return type
    }

    fun getPattern(): Pattern? {
        return pattern
    }

    private fun getTarget(request: Request?): String? {
        if (type == DeliveryServiceMatcher.Type.HOST) {
            return request.getHostname()
        }
        if (request !is HTTPRequest) {
            return null
        }
        val httpRequest = request as HTTPRequest?
        if (type == DeliveryServiceMatcher.Type.HEADER) {
            return if (httpRequest.getHeaders() != null) {
                httpRequest.getHeaders()[requestHeader]
            } else null
        }
        return if (type == DeliveryServiceMatcher.Type.PATH) {
            if (httpRequest.getQueryString() == null) {
                httpRequest.getPath()
            } else httpRequest.getPath() + "?" + httpRequest.getQueryString()
        } else null
    }

    override fun compareTo(other: RequestMatcher?): Int {
        return if (this === other || this == other) {
            0
        } else comparableRegex.compareTo(other.comparableRegex)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        val that = other as RequestMatcher?
        if (type != that.type) return false
        if (if (pattern != null) pattern.pattern() != that.pattern.pattern() else that.pattern != null) return false
        return if (if (requestHeader != null) requestHeader != that.requestHeader else that.requestHeader != null) false else !if (comparableRegex != null) comparableRegex != that.comparableRegex else that.comparableRegex != null
    }

    override fun hashCode(): Int {
        var result = type?.hashCode() ?: 0
        result = 31 * result + (pattern?.pattern()?.hashCode() ?: 0)
        result = 31 * result + (requestHeader?.hashCode() ?: 0)
        result = 31 * result + (comparableRegex?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "RequestMatcher{" +
                "type=" + type +
                ", pattern=" + pattern +
                ", requestHeader='" + requestHeader + '\'' +
                ", comparableRegex=" + comparableRegex +
                '}'
    }

    companion object {
        // This "meta" pattern is used to strip away all leading and trailing non-word characters except '.' and '-' from the original regex
        private val META_REGEX: String? = "([\\W])*([\\w-\\./]+).*"
        private val metaPattern = Pattern.compile(RequestMatcher.Companion.META_REGEX)
    }

    init {
        require(!(type == DeliveryServiceMatcher.Type.HEADER && (requestHeader == null || requestHeader.isEmpty()))) { "Request Header name must be supplied for type HEADER" }
        this.type = type
        this.requestHeader = requestHeader
        pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE)
        val matcher: Matcher = RequestMatcher.Companion.metaPattern.matcher(regex)
        matcher.matches()
        comparableRegex = ComparableStringByLength(matcher.group(2))
    }
}