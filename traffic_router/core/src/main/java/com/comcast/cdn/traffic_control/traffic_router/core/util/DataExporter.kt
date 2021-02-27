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
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestMethod
import com.comcast.cdn.traffic_control.traffic_router.core.status.model.CacheModel
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import org.springframework.http.ResponseEntity
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Steering
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node.IPVersions
import com.comcast.cdn.traffic_control.traffic_router.api.controllers.ConsistentHashController
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import java.net.URLDecoder
import java.lang.Exception
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringTarget
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringFilter
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Dispersion
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.hash.DefaultHashable
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.DeepCachingType
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import kotlin.Throws
import java.net.MalformedURLException
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
import java.net.InetAddress
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.io.IOException
import java.security.GeneralSecurityException
import java.io.UnsupportedEncodingException
import java.lang.StringBuffer
import com.comcast.cdn.traffic_control.traffic_router.core.util.StringProtector
import java.util.concurrent.atomic.AtomicInteger
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringWatcher
import java.util.function.BiConsumer
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallenge
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringResult
import com.comcast.cdn.traffic_control.traffic_router.core.config.ConfigHandler
import java.time.Instant
import com.comcast.cdn.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallengeWatcher
import java.io.FileInputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.ServerSocket
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP
import org.xbill.DNS.WireParseException
import java.net.DatagramSocket
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
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignatureManager
import com.comcast.cdn.traffic_control.traffic_router.core.router.DNSRouteResult
import org.xbill.DNS.ARecord
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.TextParseException
import java.net.Inet6Address
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
import java.io.FileWriter
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignedZoneKey
import java.security.NoSuchAlgorithmException
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
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
import java.io.ByteArrayInputStream
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
import java.io.FileOutputStream
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
import java.net.Inet4Address
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import com.comcast.cdn.traffic_control.traffic_router.core.hash.Hashable
import com.comcast.cdn.traffic_control.traffic_router.core.hash.NumberSearcher
import com.comcast.cdn.traffic_control.traffic_router.core.hash.MD5HashFunction
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
import com.comcast.cdn.traffic_control.traffic_router.core.util.LanguidState
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import com.comcast.cdn.traffic_control.traffic_router.core.util.ResourceUrl
import com.comcast.cdn.traffic_control.traffic_router.core.config.WatcherConfig
import java.io.FileReader
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractUpdatable
import org.asynchttpclient.AsyncHttpClient
import com.comcast.cdn.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
import org.asynchttpclient.DefaultAsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClientConfig
import java.io.StringReader
import org.asynchttpclient.AsyncCompletionHandler
import java.net.URISyntaxException
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
import com.comcast.cdn.traffic_control.traffic_router.core.edge.*
import com.comcast.cdn.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesResponse
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import org.springframework.context.event.ContextClosedEvent
import java.util.*

class DataExporter constructor() {
    private var trafficRouterManager: TrafficRouterManager? = null
    var statTracker: StatTracker? = null
    private var federationExporter: FederationExporter? = null
    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    val appInfo: Map<String, String>
        get() {
            val globals: MutableMap<String, String> = HashMap()
            System.getProperties().keys()
            val props: Properties = Properties()
            try {
                javaClass.getResourceAsStream("/version.prop").use({ stream -> props.load(stream) })
            } catch (e: IOException) {
                LOGGER.warn(e, e)
            }
            for (key: Any in props.keys) {
                globals.put(key as String, props.getProperty(key as String?))
            }
            return globals
        }

    fun getCachesByIp(ip: String?, geolocationProvider: String?): Map<String, Any?> {
        val map: MutableMap<String, Any?> = HashMap()
        map.put("requestIp", ip)
        val cl: Location? = getLocationFromCzm(ip)
        if (cl != null) {
            map.put("locationByCoverageZone", cl.getProperties())
        } else {
            map.put("locationByCoverageZone", NOT_FOUND_MESSAGE)
        }
        try {
            val gl: Geolocation? = trafficRouterManager.getTrafficRouter().getLocation(ip, geolocationProvider, "")
            if (gl != null) {
                map.put("locationByGeo", gl.getProperties())
            } else {
                map.put("locationByGeo", NOT_FOUND_MESSAGE)
            }
        } catch (e: GeolocationException) {
            LOGGER.warn(e, e)
            map.put("locationByGeo", e.toString())
        }
        try {
            val cidrAddress: CidrAddress = CidrAddress.Companion.fromString(ip)
            val federationsList: List<Any?>? = federationExporter!!.getMatchingFederations(cidrAddress)
            if (federationsList!!.isEmpty()) {
                map.put("locationByFederation", NOT_FOUND_MESSAGE)
            } else {
                map.put("locationByFederation", federationsList)
            }
        } catch (e: NetworkNodeException) {
            map.put("locationByFederation", NOT_FOUND_MESSAGE)
        }
        val clFromDCZ: CacheLocation? = trafficRouterManager.getTrafficRouter().getDeepCoverageZoneLocationByIP(ip)
        if (clFromDCZ != null) {
            map.put("locationByDeepCoverageZone", PropertiesAndCaches(clFromDCZ))
        } else {
            map.put("locationByDeepCoverageZone", NOT_FOUND_MESSAGE)
        }
        return map
    }

    private fun getLocationFromCzm(ip: String?): Location? {
        var nn: NetworkNode? = null
        try {
            nn = NetworkNode.Companion.getInstance()!!.getNetwork(ip)
        } catch (e: NetworkNodeException) {
            LOGGER.warn(e)
        }
        if (nn == null) {
            return null
        }
        val locId: String? = nn.getLoc()
        val cl: Location? = nn.getLocation()
        if (cl != null) {
            return cl
        }
        if (locId != null) {
            // find CacheLocation
            val trafficRouter: TrafficRouter? = trafficRouterManager.getTrafficRouter()
            val caches: Collection<CacheLocation?>? = trafficRouter.getCacheRegister().getCacheLocations()
            for (cl2: CacheLocation? in caches!!) {
                if ((cl2.getId() == locId)) {
                    return cl2
                }
            }
        }
        return null
    }

    val locations: List<String?>
        get() {
            val models: MutableList<String?> = ArrayList()
            val trafficRouter: TrafficRouter? = trafficRouterManager.getTrafficRouter()
            for (location: CacheLocation? in trafficRouter.getCacheRegister().getCacheLocations()) {
                models.add(location.getId())
            }
            Collections.sort(models)
            return models
        }

    fun getCaches(locationId: String?): List<CacheModel> {
        val trafficRouter: TrafficRouter? = trafficRouterManager.getTrafficRouter()
        val location: CacheLocation? = trafficRouter.getCacheRegister().getCacheLocation(locationId)
        return getCaches(location)
    }

    val caches: Map<String?, Any>
        get() {
            val models: MutableMap<String?, Any> = HashMap()
            val trafficRouter: TrafficRouter? = trafficRouterManager.getTrafficRouter()
            for (location: CacheLocation? in trafficRouter.getCacheRegister().getCacheLocations()) {
                models.put(location.getId(), getCaches(location.getId()))
            }
            return models
        }

    private fun getCaches(location: CacheLocation?): List<CacheModel> {
        val models: MutableList<CacheModel> = ArrayList()
        for (cache: Cache? in location!!.getCaches()) {
            val model: CacheModel = CacheModel()
            val ipAddresses: MutableList<String> = ArrayList()
            val ips: List<InetRecord?>? = cache!!.getIpAddresses(null)
            if (ips != null) {
                for (address: InetRecord? in ips) {
                    ipAddresses.add(address.getAddress().getHostAddress())
                }
            }
            model.setCacheId(cache.getId())
            model.setFqdn(cache.getFqdn())
            model.setIpAddresses(ipAddresses)
            if (cache.hasAuthority()) {
                model.setCacheOnline(cache.isAvailable())
            } else {
                model.setCacheOnline(false)
            }
            models.add(model)
        }
        return models
    }

    val cacheControlMaxAge: Int
        get() {
            var maxAge: Int = 0
            if (trafficRouterManager != null) {
                val trafficRouter: TrafficRouter? = trafficRouterManager.getTrafficRouter()
                if (trafficRouter != null) {
                    val cacheRegister: CacheRegister? = trafficRouter.getCacheRegister()
                    val config: JsonNode? = cacheRegister.getConfig()
                    if (config != null) {
                        maxAge = optInt(config, "api.cache-control.max-age")
                    }
                }
            }
            return maxAge
        }
    val staticZoneCacheStats: Map<String, Any>
        get() {
            return createCacheStatsMap(trafficRouterManager.getTrafficRouter().getZoneManager().getStaticCacheStats())
        }
    val dynamicZoneCacheStats: Map<String, Any>
        get() {
            return createCacheStatsMap(trafficRouterManager.getTrafficRouter().getZoneManager().getDynamicCacheStats())
        }

    private fun createCacheStatsMap(cacheStats: CacheStats?): Map<String, Any> {
        val cacheStatsMap: MutableMap<String, Any> = HashMap()
        cacheStatsMap.put("requestCount", cacheStats!!.requestCount())
        cacheStatsMap.put("hitCount", cacheStats.hitCount())
        cacheStatsMap.put("missCount", cacheStats.missCount())
        cacheStatsMap.put("hitRate", cacheStats.hitRate())
        cacheStatsMap.put("missRate", cacheStats.missRate())
        cacheStatsMap.put("evictionCount", cacheStats.evictionCount())
        cacheStatsMap.put("loadCount", cacheStats.loadCount())
        cacheStatsMap.put("loadSuccessCount", cacheStats.loadSuccessCount())
        cacheStatsMap.put("loadExceptionCount", cacheStats.loadExceptionCount())
        cacheStatsMap.put("loadExceptionRate", cacheStats.loadExceptionRate())
        cacheStatsMap.put("totalLoadTime", cacheStats.totalLoadTime())
        cacheStatsMap.put("averageLoadPenalty", cacheStats.averageLoadPenalty())
        return cacheStatsMap
    }

    fun setFederationExporter(federationExporter: FederationExporter?) {
        this.federationExporter = federationExporter
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger(DataExporter::class.java)
        private val NOT_FOUND_MESSAGE: String = "not found"
    }
}