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

import com.comcast.cdn.traffic_control.traffic_router.core.util.Fetcher
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.zip.GZIPInputStream
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

open class Fetcher {
    protected var timeout: Int = Fetcher.Companion.DEFAULT_TIMEOUT // override if you want something different
    protected val requestProps: MutableMap<String?, String?>? = HashMap()

    companion object {
        private val LOGGER = Logger.getLogger(Fetcher::class.java)
        protected val GET_STR: String? = "GET"
        protected val POST_STR: String? = "POST"
        protected val UTF8_STR: String? = "UTF-8"
        protected const val DEFAULT_TIMEOUT = 10000
        private val GZIP_ENCODING_STRING: String? = "gzip"
        private val CONTENT_TYPE_STRING: String? = "Content-Type"
        protected val CONTENT_TYPE_JSON: String? = "application/json"

        init {
            try {
                // TODO: make disabling self signed certificates configurable
                val ctx = SSLContext.getInstance("SSL")
                com.comcast.cdn.traffic_control.traffic_router.core.util.ctx.init(
                    null,
                    arrayOf<TrustManager?>(DefaultTrustManager()),
                    SecureRandom()
                )
                SSLContext.setDefault(com.comcast.cdn.traffic_control.traffic_router.core.util.ctx)
                HttpsURLConnection.setDefaultSSLSocketFactory(com.comcast.cdn.traffic_control.traffic_router.core.util.ctx.getSocketFactory())
            } catch (e: Exception) {
                Fetcher.Companion.LOGGER.warn(e, e)
            }
        }
    }

    private class DefaultTrustManager : X509TrustManager {
        @Throws(CertificateException::class)
        override fun checkClientTrusted(arg0: Array<X509Certificate?>?, arg1: String?) {
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(arg0: Array<X509Certificate?>?, arg1: String?) {
        }

        override fun getAcceptedIssuers(): Array<X509Certificate?>? {
            return null
        }
    }

    @Throws(IOException::class)
    protected open fun getConnection(
        url: String?,
        data: String?,
        requestMethod: String?,
        lastFetchTime: Long
    ): HttpURLConnection? {
        return getConnection(url, data, requestMethod, lastFetchTime, null)
    }

    @Throws(IOException::class)
    protected fun getConnection(
        url: String?,
        data: String?,
        requestMethod: String?,
        lastFetchTime: Long,
        contentType: String?
    ): HttpURLConnection? {
        var http: HttpURLConnection? = null
        try {
            var method: String? = Fetcher.Companion.GET_STR
            if (requestMethod != null) {
                method = requestMethod
            }
            Fetcher.Companion.LOGGER.info(method + "ing: " + url + "; timeout is " + timeout)
            val connection = URL(url).openConnection()
            connection.ifModifiedSince = lastFetchTime
            if (timeout != 0) {
                connection.connectTimeout = timeout
                connection.readTimeout = timeout
            }
            http = connection as HttpURLConnection
            if (connection is HttpsURLConnection) {
                val https = connection as HttpsURLConnection
                https.hostnameVerifier = HostnameVerifier { arg0, arg1 -> true }
            }
            http.instanceFollowRedirects = false
            http.requestMethod = method
            http.allowUserInteraction = true
            http.addRequestProperty("Accept-Encoding", Fetcher.Companion.GZIP_ENCODING_STRING)
            for (key in requestProps.keys) {
                http.addRequestProperty(key, requestProps.get(key))
            }
            if (contentType != null) {
                http.addRequestProperty(Fetcher.Companion.CONTENT_TYPE_STRING, contentType)
            }
            if (method == Fetcher.Companion.POST_STR && data != null) {
                http.doOutput = true // Triggers POST.
                http.outputStream.use { output -> output.write(data.toByteArray(charset(Fetcher.Companion.UTF8_STR))) }
            }
            connection.connect()
        } catch (e: Exception) {
            Fetcher.Companion.LOGGER.error("Failed Http Request to " + http.getURL() + " Status " + http.getResponseCode())
            http.disconnect()
        }
        return http
    }

    @Throws(IOException::class)
    fun fetchIfModifiedSince(url: String?, lastFetchTime: Long): String? {
        return fetchIfModifiedSince(url, null, null, lastFetchTime)
    }

    @Throws(IOException::class)
    private fun fetchIfModifiedSince(url: String?, data: String?, method: String?, lastFetchTime: Long): String? {
        val out: OutputStream? = null
        var ifModifiedSince: String? = null
        try {
            val connection = getConnection(url, data, method, lastFetchTime)
            if (connection != null) {
                if (connection.responseCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
                    return null
                }
                if (connection.responseCode > 399) {
                    Fetcher.Companion.LOGGER.warn("Failed Http Request to " + url + " Status " + connection.responseCode)
                    return null
                }
                val sb = StringBuilder()
                createStringBuilderFromResponse(sb, connection)
                ifModifiedSince = sb.toString()
            }
        } finally {
            IOUtils.closeQuietly(out)
        }
        return ifModifiedSince
    }

    @Throws(IOException::class)
    fun getIfModifiedSince(url: String?, lastFetchTime: Long, stringBuilder: StringBuilder?): Int {
        val out: OutputStream? = null
        var status = 0
        return try {
            val connection = getConnection(url, null, "GET", lastFetchTime)
            if (connection != null) {
                status = connection.responseCode
                if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
                    return status
                }
                if (connection.responseCode > 399) {
                    Fetcher.Companion.LOGGER.warn("Failed Http Request to " + url + " Status " + connection.responseCode)
                    return status
                }
                createStringBuilderFromResponse(stringBuilder, connection)
            }
            status
        } finally {
            IOUtils.closeQuietly(out)
        }
    }

    @JvmOverloads
    @Throws(IOException::class)
    fun fetch(url: String?, data: String? = null, method: String? = null): String? {
        return fetchIfModifiedSince(url, data, method, 0L)
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val fetcher = o as Fetcher?
        return if (timeout != fetcher.timeout) false else !if (requestProps != null) requestProps != fetcher.requestProps else fetcher.requestProps != null
    }

    override fun hashCode(): Int {
        var result = timeout
        result = 31 * result + (requestProps?.hashCode() ?: 0)
        return result
    }

    @Throws(IOException::class)
    fun createStringBuilderFromResponse(sb: StringBuilder?, connection: HttpURLConnection?) {
        if (Fetcher.Companion.GZIP_ENCODING_STRING == connection.getContentEncoding()) {
            val zippedInputStream = GZIPInputStream(connection.getInputStream())
            val r = BufferedReader(InputStreamReader(zippedInputStream))
            var input: String?
            while (r.readLine().also { input = it } != null) {
                sb.append(input)
            }
        } else {
            BufferedReader(InputStreamReader(connection.getInputStream())).use { `in` ->
                var input: String?
                while (`in`.readLine().also { input = it } != null) {
                    sb.append(input)
                }
            }
        }
    }
}