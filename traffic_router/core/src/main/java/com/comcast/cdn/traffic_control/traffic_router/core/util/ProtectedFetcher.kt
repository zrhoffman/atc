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

import java.io.IOException
import java.net.HttpCookie
import java.net.HttpURLConnection

class ProtectedFetcher(authorizationEndpoint: String?, data: String?, timeout: Int) : Fetcher() {
    private var authorizationEndpoint: String? = null
    private var data: String? = null
    private var cookie: HttpCookie? = null

    @Throws(IOException::class)
    override fun getConnection(
        url: String?,
        data: String?,
        method: String?,
        lastFetchedTime: Long
    ): HttpURLConnection? {
        if (isCookieValid()) {
            val connection = extractCookie(super.getConnection(url, data, method, lastFetchedTime))
            if (connection.getResponseCode() != HttpURLConnection.HTTP_UNAUTHORIZED) {
                return connection
            }
        }
        extractCookie(super.getConnection(getAuthorizationEndpoint(), getData(), Fetcher.Companion.POST_STR, 0L))
        return extractCookie(super.getConnection(url, data, method, lastFetchedTime))
    }

    @Throws(IOException::class)
    private fun extractCookie(http: HttpURLConnection?): HttpURLConnection? {
        if (http != null && http.getHeaderField("Set-Cookie") != null) {
            setCookie(HttpCookie.parse(http.getHeaderField("Set-Cookie"))[0])
        }
        return http
    }

    private fun isCookieValid(): Boolean {
        return if (cookie != null && !cookie.hasExpired()) {
            true
        } else {
            false
        }
    }

    private fun setCookie(cookie: HttpCookie?) {
        this.cookie = cookie
        if (this.cookie != null) {
            requestProps["Cookie"] = this.cookie.toString()
        } else {
            requestProps.remove("Cookie")
        }
    }

    private fun getAuthorizationEndpoint(): String? {
        return authorizationEndpoint
    }

    private fun setAuthorizationEndpoint(authorizationEndpoint: String?) {
        this.authorizationEndpoint = authorizationEndpoint
    }

    private fun getData(): String? {
        return data
    }

    private fun setData(data: String?) {
        this.data = data
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        if (!super.equals(o)) return false
        val that = o as ProtectedFetcher?
        if (if (authorizationEndpoint != null) authorizationEndpoint != that.authorizationEndpoint else that.authorizationEndpoint != null) return false
        return if (if (data != null) data != that.data else that.data != null) false else !if (cookie != null) cookie != that.cookie else that.cookie != null
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + if (authorizationEndpoint != null) authorizationEndpoint.hashCode() else 0
        result = 31 * result + if (data != null) data.hashCode() else 0
        result = 31 * result + if (cookie != null) cookie.hashCode() else 0
        return result
    }

    init {
        this.timeout = if (timeout > 0) timeout else Fetcher.Companion.DEFAULT_TIMEOUT
        setAuthorizationEndpoint(authorizationEndpoint)
        setData(data)
    }
}