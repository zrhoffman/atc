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

import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import java.net.URL
import java.util.Enumeration
import javax.servlet.http.HttpServletRequest

class HTTPRequest : Request {
    private var requestedUrl: String? = null
    private var path: String? = null
    private var uri: String? = null
    private var queryString: String? = null
    private var headers: MutableMap<String?, String?>? = null
    private var secure = false

    constructor() {}
    constructor(request: HttpServletRequest?) {
        applyRequest(request)
    }

    constructor(request: HttpServletRequest?, url: URL?) {
        applyRequest(request)
        applyUrl(url)
    }

    constructor(url: URL?) {
        applyUrl(url)
    }

    fun applyRequest(request: HttpServletRequest?) {
        clientIP = request.getRemoteAddr()
        setPath(request.getPathInfo())
        setQueryString(request.getQueryString())
        hostname = request.getServerName()
        setRequestedUrl(request.getRequestURL().toString())
        setUri(request.getRequestURI())
        val xmm = request.getHeader(HTTPRequest.Companion.X_MM_CLIENT_IP)
        val fip = request.getParameter(HTTPRequest.Companion.FAKE_IP)
        if (xmm != null) {
            clientIP = xmm
        } else if (fip != null) {
            clientIP = fip
        }
        val headers: MutableMap<String?, String?> = HashMap()
        val headerNames: Enumeration<*>? = request.getHeaderNames()
        while (headerNames.hasMoreElements()) {
            val name = headerNames.nextElement() as String
            val value = request.getHeader(name)
            headers[name] = value
        }
        setHeaders(headers)
        secure = request.isSecure()
    }

    fun applyUrl(url: URL?) {
        setPath(url.getPath())
        setQueryString(url.getQuery())
        hostname = url.getHost()
        setRequestedUrl(url.toString())
    }

    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is HTTPRequest) {
            val rhs = obj as HTTPRequest?
            EqualsBuilder()
                .appendSuper(super.equals(obj))
                .append(getHeaders(), rhs.getHeaders())
                .append(getPath(), rhs.getPath())
                .append(getQueryString(), rhs.getQueryString())
                .append(getUri(), rhs.getUri())
                .isEquals
        } else {
            false
        }
    }

    fun getHeaders(): MutableMap<String?, String?>? {
        return headers
    }

    fun getPath(): String? {
        return path
    }

    fun getQueryString(): String? {
        return queryString
    }

    /**
     * Gets the requested URL. This URL will not include the query string if the client provided
     * one.
     *
     * @return the requestedUrl
     */
    fun getRequestedUrl(): String? {
        return requestedUrl
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .appendSuper(super.hashCode())
            .append(getHeaders())
            .append(getPath())
            .append(getQueryString())
            .append(getUri())
            .toHashCode()
    }

    fun setHeaders(headers: MutableMap<String?, String?>?) {
        this.headers = headers
    }

    fun setPath(path: String?) {
        this.path = path
    }

    fun setQueryString(queryString: String?) {
        this.queryString = queryString
    }

    /**
     * Sets the requested URL. This URL SHOULD NOT include the query string if the client provided
     * one.
     *
     * @param requestedUrl
     * the requestedUrl to set
     */
    fun setRequestedUrl(requestedUrl: String?) {
        this.requestedUrl = requestedUrl
    }

    override fun getType(): String? {
        return "http"
    }

    fun getUri(): String? {
        return uri
    }

    fun setUri(uri: String?) {
        this.uri = uri
    }

    fun getHeaderValue(name: String?): String? {
        return if (headers != null && headers.containsKey(name)) {
            headers.get(name)
        } else null
    }

    fun isSecure(): Boolean {
        return secure
    }

    companion object {
        val X_MM_CLIENT_IP: String? = "X-MM-Client-IP"
        val FAKE_IP: String? = "fakeClientIpAddress"
    }
}