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
import java.security.GeneralSecurityException
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
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.lang.InterruptedException
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
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManager.ZoneCacheType
import java.util.stream.Collectors
import com.google.common.cache.CacheBuilderSpec
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignedZoneKey
import java.security.NoSuchAlgorithmException
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import com.comcast.cdn.traffic_control.traffic_router.core.edge.TrafficRouterLocation
import org.xbill.DNS.NSECRecord
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.CNAMERecord
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.NSRecord
import java.security.PrivateKey
import java.security.PublicKey
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
import javax.net.ssl.SSLSession
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
import com.comcast.cdn.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
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
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import org.asynchttpclient.*
import org.springframework.context.event.ContextClosedEvent
import java.io.*
import java.lang.StringBuilder
import java.net.*
import java.util.Enumeration
import java.util.concurrent.*

/**
 *
 * @author jlaue
 */
class PeriodicResourceUpdater constructor(
    private val listener: AbstractUpdatable,
    protected val urls: ResourceUrl,
    protected var databaseLocation: String,
    interval: Int,
    pauseTilLoaded: Boolean
) {
    private var asyncHttpClient: AsyncHttpClient? = null
    protected var executorService: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    protected var pollingInterval: Long
    protected var scheduledService: ScheduledFuture<*>? = null
    fun destroy() {
        executorService.shutdownNow()
        while (!asyncHttpClient!!.isClosed()) {
            try {
                asyncHttpClient!!.close()
            } catch (e: IOException) {
                LOGGER.error(e.message)
            }
        }
    }

    /**
     * Gets pollingInterval.
     *
     * @return the pollingInterval
     */
    fun getPollingInterval(): Long {
        if (pollingInterval == 0L) {
            return 66000
        }
        return pollingInterval
    }

    private val updater: Runnable = object : Runnable {
        public override fun run() {
            updateDatabase()
        }
    }
    private var hasBeenLoaded: Boolean = false
    private val pauseTilLoaded: Boolean
    fun init() {
        asyncHttpClient = newAsyncClient()
        putCurrent()
        LOGGER.info("Starting schedule with interval: " + getPollingInterval() + " : " + TimeUnit.MILLISECONDS)
        scheduledService =
            executorService.scheduleWithFixedDelay(updater, 0, getPollingInterval(), TimeUnit.MILLISECONDS)
        // wait here until something is loaded
        val existingDB: File = File(databaseLocation)
        if (pauseTilLoaded) {
            while (!existingDB.exists()) {
                LOGGER.info("Waiting for valid: " + databaseLocation)
                try {
                    Thread.sleep(getPollingInterval())
                } catch (e: InterruptedException) {
                }
            }
        }
    }

    private fun newAsyncClient(): AsyncHttpClient {
        return DefaultAsyncHttpClient(
            DefaultAsyncHttpClientConfig.Builder()
                .setFollowRedirect(true)
                .setConnectTimeout(10000)
                .build()
        )
    }

    @Synchronized
    private fun putCurrent() {
        val existingDB: File = File(databaseLocation)
        if (existingDB.exists()) {
            try {
                listener.update(IOUtils.toString(FileReader(existingDB)))
            } catch (e: Exception) {
                LOGGER.warn(e, e)
            }
        }
    }

    @Synchronized
    fun updateDatabase(): Boolean {
        val existingDB: File = File(databaseLocation)
        try {
            if (!hasBeenLoaded || needsUpdating(existingDB)) {
                val request: Request? = getRequest(urls.nextUrl())
                if (request != null) {
                    request.getHeaders().add("Accept-Encoding", GZIP_ENCODING_STRING)
                    if ((asyncHttpClient != null) && (!asyncHttpClient!!.isClosed())) {
                        asyncHttpClient!!.executeRequest<Any>(
                            request,
                            UpdateHandler(request)
                        ) // AsyncHandlers are NOT thread safe; one instance per request
                    }
                    return true
                }
            } else {
                LOGGER.info("Database " + existingDB.getAbsolutePath() + " does not require updating.")
            }
        } catch (e: Exception) {
            LOGGER.warn(e.message, e)
        }
        return false
    }

    fun updateDatabase(newDB: String?): Boolean {
        val existingDB: File = File(databaseLocation)
        try {
            if (newDB != null && !filesEqual(existingDB, newDB)) {
                listener.cancelUpdate()
                if (listener.update(newDB)) {
                    copyDatabase(existingDB, newDB)
                    LOGGER.info("updated " + existingDB.getAbsolutePath())
                    listener.setLastUpdated(System.currentTimeMillis())
                    listener.complete()
                } else {
                    LOGGER.warn("File rejected: " + existingDB.getAbsolutePath())
                }
            } else {
                listener.noChange()
            }
            hasBeenLoaded = true
            return true
        } catch (e: Exception) {
            LOGGER.warn(e.message, e)
        }
        return false
    }

    fun setDatabaseLocation(databaseLocation: String) {
        this.databaseLocation = databaseLocation
    }

    /**
     * Sets executorService.
     *
     * @param es
     * the executorService to set
     */
    fun setExecutorService(es: ScheduledExecutorService) {
        executorService = es
    }

    /**
     * Sets pollingInterval.
     *
     * @param pollingInterval
     * the pollingInterval to set
     */
    fun setPollingInterval(pollingInterval: Long) {
        this.pollingInterval = pollingInterval
    }

    @Throws(IOException::class)
    private fun fileMd5(file: File): String {
        FileInputStream(file).use({ stream -> return DigestUtils.md5Hex(stream) })
    }

    @Throws(IOException::class)
    fun filesEqual(a: File, newDB: String?): Boolean {
        if (!a.exists()) {
            return newDB == null
        }
        if (newDB == null) {
            return false
        }
        if (a.length() != newDB.length.toLong()) {
            return false
        }
        IOUtils.toInputStream(newDB).use({ newDBStream -> return (fileMd5(a) == DigestUtils.md5Hex(newDBStream)) })
    }

    @Synchronized
    @Throws(IOException::class)
    protected fun copyDatabase(existingDB: File, newDB: String?) {
        StringReader(newDB).use({ `in` ->
            FileOutputStream(existingDB).use({ out ->
                out.getChannel().tryLock().use({ lock ->
                    if (lock == null) {
                        LOGGER.error("Database " + existingDB.getAbsolutePath() + " locked by another process.")
                        return
                    }
                    IOUtils.copy(`in`, out)
                    existingDB.setReadable(true, false)
                    existingDB.setWritable(true, true)
                    lock.release()
                })
            })
        })
    }

    protected fun needsUpdating(existingDB: File): Boolean {
        val now: Long = System.currentTimeMillis()
        val fileTime: Long = existingDB.lastModified()
        val pollingIntervalInMS: Long = getPollingInterval()
        return ((fileTime + pollingIntervalInMS) < now)
    }

    private inner class UpdateHandler constructor(val request: Request) : AsyncCompletionHandler<Any>() {
        @Throws(IOException::class)
        public override fun onCompleted(response: Response): Int {
            // Do something with the Response
            val code: Int = response.getStatusCode()
            if (code != 200) {
                if (code >= 400) {
                    LOGGER.warn("failed to GET " + response.getUri() + " - returned status code " + code)
                }
                return code
            }
            val responseBody: String
            if ((GZIP_ENCODING_STRING == response.getHeader("Content-Encoding"))) {
                val stringBuilder: StringBuilder = StringBuilder()
                val zippedInputStream: GZIPInputStream = GZIPInputStream(response.getResponseBodyAsStream())
                val r: BufferedReader = BufferedReader(InputStreamReader(zippedInputStream))
                var line: String?
                while ((r.readLine().also({ line = it })) != null) {
                    stringBuilder.append(line)
                }
                responseBody = stringBuilder.toString()
            } else {
                responseBody = response.getResponseBody()
            }
            updateDatabase(responseBody)
            return code
        }

        public override fun onThrowable(t: Throwable) {
            LOGGER.warn("Failed request " + request.getUrl() + ": " + t, t)
        }
    }

    private fun getRequest(url: String?): Request? {
        try {
            URI(url)
            return asyncHttpClient!!.prepareGet(url).setFollowRedirect(true).build()
        } catch (e: URISyntaxException) {
            LOGGER.fatal("Cannot update database from Bad URI - " + url)
            return null
        }
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger(PeriodicResourceUpdater::class.java)
        private val GZIP_ENCODING_STRING: String = "gzip"
    }

    init {
        pollingInterval = interval.toLong()
        this.pauseTilLoaded = pauseTilLoaded
    }
}