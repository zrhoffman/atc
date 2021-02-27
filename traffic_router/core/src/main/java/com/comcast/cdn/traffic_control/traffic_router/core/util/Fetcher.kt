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

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.beans.factory.annotation.Autowired
import com.comcast.cdn.traffic_control.traffic_router.core.util.DataExporter
import org.springframework.web.bind.annotation.ResponseBody
import java.util.HashMap
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestMethod
import com.comcast.cdn.traffic_control.traffic_router.core.status.model.CacheModel
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import org.springframework.http.ResponseEntity
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Steering
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node.IPVersions
import com.comcast.cdn.traffic_control.traffic_router.api.controllers.ConsistentHashController
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import java.lang.Exception
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringTarget
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringFilter
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Dispersion
import java.util.SortedMap
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.hash.DefaultHashable
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import java.util.HashSet
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.DeepCachingType
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import kotlin.Throws
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.util.SortedSet
import java.util.TreeSet
import java.lang.StringBuffer
import com.comcast.cdn.traffic_control.traffic_router.core.util.StringProtector
import java.util.concurrent.atomic.AtomicInteger
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringWatcher
import java.util.function.BiConsumer
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import java.util.TreeMap
import com.comcast.cdn.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallenge
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringResult
import com.comcast.cdn.traffic_control.traffic_router.core.config.ConfigHandler
import java.time.Instant
import com.comcast.cdn.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallengeWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP
import org.xbill.DNS.WireParseException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import org.xbill.DNS.OPTRecord
import java.lang.Runnable
import java.util.concurrent.ExecutorService
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.util.concurrent.TimeUnit
import java.lang.InterruptedException
import java.util.concurrent.ExecutionException
import org.xbill.DNS.Rcode
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneKey
import java.text.SimpleDateFormat
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneUtils
import java.util.Calendar
import java.lang.RuntimeException
import org.xbill.DNS.EDNSOption
import org.xbill.DNS.DClass
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.ClientSubnetOption
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManager
import org.xbill.DNS.SetResponse
import org.xbill.DNS.RRset
import org.xbill.DNS.SOARecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import org.xbill.DNS.DNSKEYRecord
import org.xbill.DNS.DSRecord
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignatureManager
import com.comcast.cdn.traffic_control.traffic_router.core.router.DNSRouteResult
import org.xbill.DNS.ARecord
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.TextParseException
import com.google.common.cache.CacheStats
import java.util.concurrent.ConcurrentMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManager.ZoneCacheType
import java.util.concurrent.Callable
import java.util.stream.Collectors
import com.google.common.cache.CacheBuilderSpec
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignedZoneKey
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import com.comcast.cdn.traffic_control.traffic_router.core.edge.TrafficRouterLocation
import org.xbill.DNS.NSECRecord
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.CNAMERecord
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.NSRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRSetsBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServerMain
import kotlin.jvm.JvmStatic
import org.springframework.context.support.ClassPathXmlApplicationContext
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSigner
import java.util.stream.StreamSupport
import org.xbill.DNS.DNSSEC
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import java.util.function.ToIntFunction
import com.comcast.cdn.traffic_control.traffic_router.core.util.ProtectedFetcher
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import org.xbill.DNS.DNSSEC.DNSSECException
import com.comcast.cdn.traffic_control.traffic_router.secure.BindPrivateKey
import org.xbill.DNS.Master
import java.text.DecimalFormat
import java.math.RoundingMode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationMapping
import com.comcast.cdn.traffic_control.traffic_router.core.loc.Federation
import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpWhitelist
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIp
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import com.google.common.net.InetAddresses
import com.maxmind.geoip2.model.AnonymousIpResponse
import com.comcast.cdn.traffic_control.traffic_router.core.router.HTTPRouteResult
import kotlin.jvm.JvmOverloads
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode.SuperNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoDsvc
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeo
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule.PostalsType
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoCoordinateRange
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult.RegionalGeoResultType
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AbstractServiceUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableTreeSet
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationMappingBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoUpdater
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.zip.GZIPInputStream
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpConfigUpdater
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationService
import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.model.CityResponse
import com.maxmind.geoip2.exception.AddressNotFoundException
import com.comcast.cdn.traffic_control.traffic_router.core.loc.MaxmindGeolocationService
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseService
import com.maxmind.geoip2.exception.GeoIp2Exception
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseUpdater
import org.apache.commons.lang3.builder.HashCodeBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import com.comcast.cdn.traffic_control.traffic_router.core.hash.Hashable
import com.comcast.cdn.traffic_control.traffic_router.core.hash.NumberSearcher
import com.comcast.cdn.traffic_control.traffic_router.core.hash.MD5HashFunction
import java.util.NoSuchElementException
import org.springframework.web.filter.OncePerRequestFilter
import com.comcast.cdn.traffic_control.traffic_router.core.http.HTTPAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.http.RouterFilter
import com.comcast.cdn.traffic_control.traffic_router.core.http.HTTPAccessEventBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.http.HttpAccessRequestHeaders
import com.comcast.cdn.traffic_control.traffic_router.core.util.Fetcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.Fetcher.DefaultTrustManager
import java.lang.NumberFormatException
import com.comcast.cdn.traffic_control.traffic_router.core.util.FederationExporter
import com.comcast.cdn.traffic_control.traffic_router.core.edge.PropertiesAndCaches
import com.comcast.cdn.traffic_control.traffic_router.core.util.LanguidState
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import com.comcast.cdn.traffic_control.traffic_router.core.util.ResourceUrl
import com.comcast.cdn.traffic_control.traffic_router.core.config.WatcherConfig
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractUpdatable
import org.asynchttpclient.AsyncHttpClient
import com.comcast.cdn.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
import org.asynchttpclient.DefaultAsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClientConfig
import org.asynchttpclient.AsyncCompletionHandler
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableStringByLength
import com.comcast.cdn.traffic_control.traffic_router.core.loc.GeolocationDatabaseUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.DeepNetworkUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesPoller
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesPublisher
import java.util.concurrent.atomic.AtomicBoolean
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorWatcher
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.comcast.cdn.traffic_control.traffic_router.core.config.CertificateChecker
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.RouteType
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultCode
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Tallies
import com.comcast.cdn.traffic_control.traffic_router.core.hash.ConsistentHasher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringGeolocationComparator
import com.comcast.cdn.traffic_control.traffic_router.core.router.LocationComparator
import org.springframework.beans.BeansException
import com.comcast.cdn.traffic_control.traffic_router.configuration.ConfigurationListener
import com.comcast.cdn.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesResponse
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import org.springframework.context.event.ContextClosedEvent
import java.io.*
import java.lang.StringBuilder
import java.net.*
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Enumeration
import javax.net.ssl.*

open class Fetcher constructor() {
    protected var timeout: Int = DEFAULT_TIMEOUT // override if you want something different
    protected val requestProps: Map<String, String>? = HashMap()

    companion object {
        private val LOGGER: Logger = Logger.getLogger(Fetcher::class.java)
        protected val GET_STR: String = "GET"
        protected val POST_STR: String = "POST"
        protected val UTF8_STR: String = "UTF-8"
        protected val DEFAULT_TIMEOUT: Int = 10000
        private val GZIP_ENCODING_STRING: String = "gzip"
        private val CONTENT_TYPE_STRING: String = "Content-Type"
        protected val CONTENT_TYPE_JSON: String = "application/json"

        init {
            try {
                // TODO: make disabling self signed certificates configurable
                val ctx: SSLContext = SSLContext.getInstance("SSL")
                com.comcast.cdn.traffic_control.traffic_router.core.util.ctx.init(
                    null,
                    arrayOf<TrustManager>(DefaultTrustManager()),
                    SecureRandom()
                )
                SSLContext.setDefault(com.comcast.cdn.traffic_control.traffic_router.core.util.ctx)
                HttpsURLConnection.setDefaultSSLSocketFactory(com.comcast.cdn.traffic_control.traffic_router.core.util.ctx.getSocketFactory())
            } catch (e: Exception) {
                LOGGER.warn(e, e)
            }
        }
    }

    private class DefaultTrustManager constructor() : X509TrustManager {
        @Throws(CertificateException::class)
        public override fun checkClientTrusted(arg0: Array<X509Certificate>, arg1: String) {
        }

        @Throws(CertificateException::class)
        public override fun checkServerTrusted(arg0: Array<X509Certificate>, arg1: String) {
        }

        public override fun getAcceptedIssuers(): Array<X509Certificate> {
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
            var method: String = GET_STR
            if (requestMethod != null) {
                method = requestMethod
            }
            LOGGER.info(method + "ing: " + url + "; timeout is " + timeout)
            val connection: URLConnection = URL(url).openConnection()
            connection.setIfModifiedSince(lastFetchTime)
            if (timeout != 0) {
                connection.setConnectTimeout(timeout)
                connection.setReadTimeout(timeout)
            }
            http = connection as HttpURLConnection?
            if (connection is HttpsURLConnection) {
                connection.setHostnameVerifier(object : HostnameVerifier {
                    public override fun verify(arg0: String, arg1: SSLSession): Boolean {
                        return true
                    }
                })
            }
            http!!.setInstanceFollowRedirects(false)
            http.setRequestMethod(method)
            http.setAllowUserInteraction(true)
            http.addRequestProperty("Accept-Encoding", GZIP_ENCODING_STRING)
            for (key: String in requestProps!!.keys) {
                http.addRequestProperty(key, requestProps.get(key))
            }
            if (contentType != null) {
                http.addRequestProperty(CONTENT_TYPE_STRING, contentType)
            }
            if ((method == POST_STR) && data != null) {
                http.setDoOutput(true) // Triggers POST.
                http.getOutputStream().use({ output -> output.write(data.toByteArray(charset(UTF8_STR))) })
            }
            connection.connect()
        } catch (e: Exception) {
            LOGGER.error("Failed Http Request to " + http!!.getURL() + " Status " + http.getResponseCode())
            http.disconnect()
        }
        return http
    }

    @Throws(IOException::class)
    fun fetchIfModifiedSince(url: String, lastFetchTime: Long): String? {
        return fetchIfModifiedSince(url, null, null, lastFetchTime)
    }

    @Throws(IOException::class)
    private fun fetchIfModifiedSince(url: String, data: String?, method: String?, lastFetchTime: Long): String? {
        val out: OutputStream? = null
        var ifModifiedSince: String? = null
        try {
            val connection: HttpURLConnection? = getConnection(url, data, method, lastFetchTime)
            if (connection != null) {
                if (connection.getResponseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
                    return null
                }
                if (connection.getResponseCode() > 399) {
                    LOGGER.warn("Failed Http Request to " + url + " Status " + connection.getResponseCode())
                    return null
                }
                val sb: StringBuilder = StringBuilder()
                createStringBuilderFromResponse(sb, connection)
                ifModifiedSince = sb.toString()
            }
        } finally {
            IOUtils.closeQuietly(out)
        }
        return ifModifiedSince
    }

    @Throws(IOException::class)
    fun getIfModifiedSince(url: String, lastFetchTime: Long, stringBuilder: StringBuilder): Int {
        val out: OutputStream? = null
        var status: Int = 0
        try {
            val connection: HttpURLConnection? = getConnection(url, null, "GET", lastFetchTime)
            if (connection != null) {
                status = connection.getResponseCode()
                if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
                    return status
                }
                if (connection.getResponseCode() > 399) {
                    LOGGER.warn("Failed Http Request to " + url + " Status " + connection.getResponseCode())
                    return status
                }
                createStringBuilderFromResponse(stringBuilder, connection)
            }
            return status
        } finally {
            IOUtils.closeQuietly(out)
        }
    }

    @JvmOverloads
    @Throws(IOException::class)
    fun fetch(url: String, data: String? = null, method: String? = null): String? {
        return fetchIfModifiedSince(url, data, method, 0L)
    }

    public override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val fetcher: Fetcher = o as Fetcher
        if (timeout != fetcher.timeout) return false
        return !(if (requestProps != null) !(requestProps == fetcher.requestProps) else fetcher.requestProps != null)
    }

    public override fun hashCode(): Int {
        var result: Int = timeout
        result = 31 * result + (if (requestProps != null) requestProps.hashCode() else 0)
        return result
    }

    @Throws(IOException::class)
    fun createStringBuilderFromResponse(sb: StringBuilder, connection: HttpURLConnection) {
        if ((GZIP_ENCODING_STRING == connection.getContentEncoding())) {
            val zippedInputStream: GZIPInputStream = GZIPInputStream(connection.getInputStream())
            val r: BufferedReader = BufferedReader(InputStreamReader(zippedInputStream))
            var input: String?
            while ((r.readLine().also({ input = it })) != null) {
                sb.append(input)
            }
        } else {
            BufferedReader(InputStreamReader(connection.getInputStream())).use({ `in` ->
                var input: String?
                while ((`in`.readLine().also({ input = it })) != null) {
                    sb.append(input)
                }
            })
        }
    }
}