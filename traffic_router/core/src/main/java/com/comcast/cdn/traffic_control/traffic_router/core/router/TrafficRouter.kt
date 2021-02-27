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
package com.comcast.cdn.traffic_control.traffic_router.core.router

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
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
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
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import java.lang.Runnable
import java.util.concurrent.ExecutorService
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.util.concurrent.TimeUnit
import java.lang.InterruptedException
import java.util.concurrent.ExecutionException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneKey
import java.text.SimpleDateFormat
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneUtils
import java.lang.RuntimeException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManager
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignatureManager
import com.comcast.cdn.traffic_control.traffic_router.core.router.DNSRouteResult
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
import java.security.PrivateKey
import java.security.PublicKey
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRSetsBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServerMain
import kotlin.jvm.JvmStatic
import org.springframework.context.support.ClassPathXmlApplicationContext
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSigner
import java.util.stream.StreamSupport
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import java.util.function.ToIntFunction
import com.comcast.cdn.traffic_control.traffic_router.core.util.ProtectedFetcher
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import org.xbill.DNS.DNSSEC.DNSSECException
import com.comcast.cdn.traffic_control.traffic_router.secure.BindPrivateKey
import java.io.ByteArrayInputStream
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
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesResponse
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import org.springframework.context.ApplicationContext
import org.springframework.context.event.ContextClosedEvent
import org.xbill.DNS.*
import java.lang.StringBuilder
import java.net.*
import java.util.*
import java.util.function.Predicate
import java.util.regex.Matcher
import java.util.regex.Pattern

/**
 * TrafficRouter is the main router class that handles Traffic Router logic.
 */
class TrafficRouter constructor(
    cr: CacheRegister,
    geolocationService: GeolocationService?,
    geolocationService6: GeolocationService?,
    anonymousIpService: AnonymousIpDatabaseService?,
    statTracker: StatTracker?,
    trafficOpsUtils: TrafficOpsUtils?,
    federationRegistry: FederationRegistry?,
    trafficRouterManager: TrafficRouterManager
) {
    val cacheRegister: CacheRegister?
    val zoneManager: ZoneManager
    val geolocationService: GeolocationService?
    private val geolocationService6: GeolocationService?
    val anonymousIpDatabaseService: AnonymousIpDatabaseService?
    private val federationRegistry: FederationRegistry?
    val isConsistentDNSRouting: Boolean
    val isClientSteeringDiversityEnabled: Boolean
    val isDnssecZoneDiffingEnabled: Boolean
    val isEdgeDNSRouting: Boolean
    val isEdgeHTTPRouting: Boolean
    private var edgeNSttl // 1 hour default
            : Long = 0
    private val edgeDNSRoutingLimit: Int
    private val edgeHTTPRoutingLimit: Int
    private val random: Random = Random(System.nanoTime())
    var requestHeaders: MutableSet<String?> = HashSet()
    private var applicationContext: ApplicationContext? = null
    private val consistentHasher: ConsistentHasher = ConsistentHasher()
    private var steeringRegistry: SteeringRegistry? = null
    private val defaultGeolocationsOverride: MutableMap<String, Geolocation> = HashMap()

    /**
     * Returns a [List] of all of the online [Cache]s that support the specified
     * [DeliveryService]. If no online caches are found to support the specified
     * DeliveryService an empty list is returned.
     *
     * @param ds
     * the DeliveryService to check
     * @return collection of supported caches
     */
    fun getSupportingCaches(
        caches: List<Cache?>?,
        ds: DeliveryService?,
        requestVersion: IPVersions?
    ): MutableList<Cache?> {
        val supportingCaches: MutableList<Cache?> = ArrayList()
        for (cache: Cache? in caches!!) {
            if (!cache!!.hasDeliveryService(ds.getId())) {
                continue
            }
            if (!cache.hasAuthority() || (cache.isAvailable(requestVersion))) {
                supportingCaches.add(cache)
            }
        }
        return supportingCaches
    }

    /**
     * Selects a Delivery Service to service a request.
     *
     * @param request The request being served
     * @return A Delivery Service to use when servicing the request.
     */
    protected fun selectDeliveryService(request: Request): DeliveryService? {
        if (cacheRegister == null) {
            LOGGER.warn("no caches yet")
            return null
        }
        val deliveryService: DeliveryService? = cacheRegister.getDeliveryService(request)
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Selected DeliveryService: " + deliveryService)
        }
        return deliveryService
    }

    /**
     * Sets the cache server and Delivery Service "states" based on input JSON.
     *
     *
     * The input `states` is expected to be an object with (at least) two keys:
     * "caches" and "deliveryServices", which contain the states of the cache servers and
     * Delivery Services, respectively. @see #setDsStates(JsonNode) and
     * [.setCacheStates] for the expected format of those objects themselves.
     *
     * @return Always returns `true` when successful. On failure, throws.
     */
    @Throws(UnknownHostException::class)
    fun setState(states: JsonNode): Boolean {
        setCacheStates(states.get("caches"))
        setDsStates(states.get("deliveryServices"))
        return true
    }

    /**
     * Sets Delivery Service states based on the input JSON.
     *
     *
     * Delivery Services present in the input which aren't registered are ignored.
     *
     * @param dsStates The input JSON object. Expected to be a map of Delivery Service XMLIDs to
     * "state" strings.
     * @return `false` iff dsStates was `null`, otherwise `true`.
     */
    private fun setDsStates(dsStates: JsonNode?): Boolean {
        if (dsStates == null) {
            return false
        }
        val dsMap: Map<String?, DeliveryService?>? = cacheRegister.getDeliveryServices()
        for (dsName: String? in dsMap!!.keys) {
            dsMap.get(dsName)!!.setState(dsStates.get(dsName))
        }
        return true
    }

    /**
     * Sets [Cache] states based on the input JSON.
     *
     *
     * Caches present in the input which are not registered are ignored.
     *
     * @param cacheStates The input JSON object. Expected to be a map of identifying Cache names
     * to "state" strings.
     * @return `false` iff cacheStates was `null`, otherwise `true`.
     */
    private fun setCacheStates(cacheStates: JsonNode?): Boolean {
        if (cacheStates == null) {
            return false
        }
        val cacheMap: Map<String?, Cache?>? = cacheRegister.getCacheMap()
        if (cacheMap == null) {
            return false
        }
        for (cacheName: String? in cacheMap.keys) {
            val monitorCacheName: String = cacheName!!.replaceFirst("@.*".toRegex(), "")
            val state: JsonNode = cacheStates.get(monitorCacheName)
            cacheMap.get(cacheName)!!.setState(state)
        }
        return true
    }

    /**
     * Geo-locates the client returning a physical location for routing purposes.
     *
     * @param clientIP The client's network location - as a [String]. This should ideally be
     * an IP address, but trailing port number specifications are stripped.
     * @throws GeolocationException if the client could not be located.
     */
    @Throws(GeolocationException::class)
    fun getLocation(clientIP: String?): Geolocation {
        return if (clientIP!!.contains(":")) geolocationService6!!.location(clientIP) else geolocationService!!.location(
            clientIP
        )
    }

    /**
     * Retrieves a service for geo-locating clients for a specific Delivery Service.
     *
     * @param geolocationProvider The name of the provider for geo-location information (currently
     * only "Maxmind" and "Neustar" are supported)
     * @param deliveryServiceId Currently only used for logging error information, should be an
     * identifier for a Delivery Service
     * @return A [GeolocationService] that can be used to geo-locate clients *or*
     * `null` if an error occurs.
     */
    private fun getGeolocationService(geolocationProvider: String?, deliveryServiceId: String?): GeolocationService? {
        if (applicationContext == null) {
            LOGGER.error("ApplicationContext not set unable to use custom geolocation service providers")
            return null
        }
        if (geolocationProvider == null || geolocationProvider.isEmpty()) {
            return null
        }
        try {
            return applicationContext!!.getBean(geolocationProvider) as GeolocationService?
        } catch (e: Exception) {
            var error: StringBuilder =
                StringBuilder("Failed getting providing class '" + geolocationProvider + "' for geolocation")
            if (deliveryServiceId != null && !deliveryServiceId.isEmpty()) {
                error = error.append(" for delivery service " + deliveryServiceId)
            }
            error = error.append(" falling back to " + MaxmindGeolocationService::class.java.getSimpleName())
            LOGGER.error(error)
        }
        return null
    }

    /**
     * Retrieves a location for a given client being served a given Delivery Service using a
     * specific provider.
     * @param clientIP The client's network location - as a [String]. This should ideally be
     * an IP address, but trailing port number specifications are stripped.
     * @param geolocationProvider The name of the provider for geo-location information (currently
     * only "Maxmind" and "Neustar" are supported)
     * @param deliveryServiceId Currently only used for logging error information, should be an
     * identifier for a Delivery Service
     * @throws GeolocationException if the client could not be located.
     */
    @Throws(GeolocationException::class)
    fun getLocation(clientIP: String?, geolocationProvider: String?, deliveryServiceId: String?): Geolocation {
        val customGeolocationService: GeolocationService? =
            getGeolocationService(geolocationProvider, deliveryServiceId)
        return if (customGeolocationService != null) customGeolocationService.location(clientIP) else getLocation(
            clientIP
        )
    }

    /**
     * Retrieves a location for a given client being served a given Delivery Service.
     * @param clientIP The client's network location - as a [String]. This should ideally be
     * an IP address, but trailing port number specifications are stripped.
     * @param deliveryService The Delivery Service being served to the client.
     * @throws GeolocationException if the client could not be located.
     */
    @Throws(GeolocationException::class)
    fun getLocation(clientIP: String?, deliveryService: DeliveryService?): Geolocation {
        return getLocation(clientIP, deliveryService.getGeolocationProvider(), deliveryService.getId())
    }

    /**
     * Gets a [List] of [Cache]s that are capabable of serving a given Delivery Service.
     *
     *
     * The caches chosen are from the closest, non-empty, cache location to the client's physical
     * location, up to the Location Limit ([DeliveryService.getLocationLimit]) of the
     * Delivery Service being served.
     *
     * @param ds The Delivery Service being served.
     * @param clientLocation The physical location of the requesting client.
     * @param track The [Track] object on which a result location shall be set, should one be found
     * @return A [List] of [Cache]s that should be used to service a request should such a collection be found, or
     * `null` if the no applicable [Cache]s could be found.
     */
    @Throws(GeolocationException::class)
    fun getCachesByGeo(
        ds: DeliveryService?,
        clientLocation: Geolocation?,
        track: StatTracker.Track,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        var locationsTested: Int = 0
        val locationLimit: Int = ds.getLocationLimit()
        val geoEnabledCacheLocations: List<CacheLocation?> =
            filterEnabledLocations(cacheRegister.getCacheLocations(), LocalizationMethod.GEO)
        val cacheLocations1: List<CacheLocation?>? = ds!!.filterAvailableLocations(geoEnabledCacheLocations)
        val cacheLocations: List<CacheLocation?>? =
            orderLocations(cacheLocations1, clientLocation) as List<CacheLocation?>?
        for (location: CacheLocation? in cacheLocations!!) {
            val caches: MutableList<Cache?>? = selectCaches(location, ds, requestVersion)
            if (caches != null) {
                track.setResultLocation(location.getGeolocation())
                if ((track.getResultLocation() == GEO_ZERO_ZERO)) {
                    LOGGER.error("Location " + location.getId() + " has Geolocation " + location.getGeolocation())
                }
                return caches
            }
            locationsTested++
            if (locationLimit != 0 && locationsTested >= locationLimit) {
                return null
            }
        }
        return null
    }
    /**
     * Selects [Cache]s to serve a request for a Delivery Service.
     * @param request The HTTP request made by the client.
     * @param ds The Delivery Service being served.
     * @param track The [Track] object that tracks how requests are served
     * @param enableDeep Sets whether or not "Deep Caching" may be used.
     */
    /**
     * Selects [Cache]s to serve a request for a Delivery Service.
     *
     *
     * This is equivalent to calling
     * [.selectCaches] with the "deep" parameter
     * set to `true`.
     *
     * @param request The HTTP request made by the client.
     * @param ds The Delivery Service being served.
     * @param track The [Track] object that tracks how requests are served
     */
    @Throws(GeolocationException::class)
    protected fun selectCaches(
        request: HTTPRequest,
        ds: DeliveryService?,
        track: StatTracker.Track,
        enableDeep: Boolean = true
    ): MutableList<Cache?>? {
        var cacheLocation: CacheLocation?
        var result: ResultType = ResultType.CZ
        val useDeep: Boolean = enableDeep && (ds.getDeepCache() == DeepCachingType.ALWAYS)
        val requestVersion: IPVersions =
            if (request.getClientIP().contains(":")) IPVersions.IPV6ONLY else IPVersions.IPV4ONLY
        if (useDeep) {
            // Deep caching is enabled. See if there are deep caches available
            cacheLocation = getDeepCoverageZoneCacheLocation(request.getClientIP(), ds, requestVersion)
            if (cacheLocation != null && cacheLocation.getCaches().size != 0) {
                // Found deep caches for this client, and there are caches that might be available there.
                result = ResultType.DEEP_CZ
            } else {
                // No deep caches for this client, would have used them if there were any. Fallback to regular CZ
                cacheLocation = getCoverageZoneCacheLocation(request.getClientIP(), ds, requestVersion)
            }
        } else {
            // Deep caching not enabled for this Delivery Service; use the regular CZ
            cacheLocation = getCoverageZoneCacheLocation(request.getClientIP(), ds, false, track, requestVersion)
        }
        var caches: MutableList<Cache?>? = selectCachesByCZ(ds, cacheLocation, track, result, requestVersion)
        if (caches != null) {
            return caches
        }
        if (ds!!.isCoverageZoneOnly()) {
            if (ds.getGeoRedirectUrl() != null) {
                //use the NGB redirect
                caches = enforceGeoRedirect(track, ds, request.getClientIP(), null, requestVersion)
            } else {
                track.setResult(ResultType.MISS)
                track.setResultDetails(ResultDetails.DS_CZ_ONLY)
            }
        } else if (track.continueGeo) {
            // continue Geo can be disabled when backup group is used -- ended up an empty cache list if reach here
            caches = selectCachesByGeo(request.getClientIP(), ds, cacheLocation, track, requestVersion)
        }
        return caches
    }

    /**
     * Returns whether or not a Delivery Service has a valid miss location.
     * @param deliveryService The Delivery Service being served.
     */
    fun isValidMissLocation(deliveryService: DeliveryService?): Boolean {
        if ((deliveryService.getMissLocation() != null) && (deliveryService.getMissLocation()
                .getLatitude() != 0.0) && (deliveryService.getMissLocation().getLongitude() != 0.0)
        ) {
            return true
        }
        return false
    }

    /**
     * Selects [Cache]s to serve a request for a Delivery Service based on a given location.
     * @param clientIp The requesting client's IP address - as a String.
     * @param deliveryService The Delivery Service being served.
     * @param cacheLocation A selected [CacheLocation] from which [Cache]s will be
     * extracted based on the client's location.
     * @param track The [Track] object that tracks how requests are served
     */
    @Throws(GeolocationException::class)
    fun selectCachesByGeo(
        clientIp: String?,
        deliveryService: DeliveryService?,
        cacheLocation: CacheLocation?,
        track: StatTracker.Track,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        var clientLocation: Geolocation? = null
        try {
            clientLocation = getClientLocation(clientIp, deliveryService, cacheLocation, track)
        } catch (e: GeolocationException) {
            LOGGER.warn("Failed looking up Client GeoLocation: " + e.message)
        }
        if (clientLocation == null) {
            if (deliveryService.getGeoRedirectUrl() != null) {
                //will use the NGB redirect
                LOGGER.debug(
                    String.format(
                        "client is blocked by geolimit, use the NGB redirect url: %s",
                        deliveryService.getGeoRedirectUrl()
                    )
                )
                return enforceGeoRedirect(
                    track,
                    deliveryService,
                    clientIp,
                    track.getClientGeolocation(),
                    requestVersion
                )
            } else {
                track.setResultDetails(ResultDetails.DS_CLIENT_GEO_UNSUPPORTED)
                return null
            }
        }
        track.setResult(ResultType.GEO)
        if (clientLocation.isDefaultLocation() && defaultGeoLocationsOverride.containsKey(clientLocation.getCountryCode())) {
            if (isValidMissLocation(deliveryService)) {
                clientLocation = deliveryService.getMissLocation()
                track.setResult(ResultType.GEO_DS)
            } else {
                clientLocation = defaultGeoLocationsOverride.get(clientLocation.getCountryCode())
            }
        }
        val caches: MutableList<Cache?>? = getCachesByGeo(deliveryService, clientLocation, track, requestVersion)
        if (caches == null || caches.isEmpty()) {
            track.setResultDetails(ResultDetails.GEO_NO_CACHE_FOUND)
        }
        return caches
    }

    /**
     * Routes a single DNS request.
     * @param request The client request being routed.
     * @param track A "tracker" that tracks the results of routing.
     * @return The final result of routing.
     */
    @Throws(GeolocationException::class)
    fun route(request: DNSRequest, track: StatTracker.Track): DNSRouteResult? {
        val ds: DeliveryService? = selectDeliveryService(request)
        track.setRouteType(RouteType.DNS, request.getHostname())

        // TODO: getHostname or getName -- !ds.getRoutingName().equalsIgnoreCase(request.getHostname().split("\\.")[0]))
        if ((ds != null) && ds.isDns() && request.getName().toString().toLowerCase()
                .matches(ds.getRoutingName().toLowerCase() + "\\..*")
        ) {
            return getEdgeCaches(request, ds, track)
        } else {
            return getEdgeTrafficRouters(request, ds, track)
        }
    }

    @Throws(GeolocationException::class)
    private fun getEdgeTrafficRouters(
        request: DNSRequest,
        ds: DeliveryService?,
        track: StatTracker.Track
    ): DNSRouteResult {
        val result: DNSRouteResult = DNSRouteResult()
        result.setDeliveryService(ds)
        result.setAddresses(selectTrafficRouters(request, ds, track))
        return result
    }

    @Throws(GeolocationException::class)
    private fun selectTrafficRouters(
        request: DNSRequest,
        ds: DeliveryService?,
        track: StatTracker.Track? = null
    ): MutableList<InetRecord?> {
        val result: MutableList<InetRecord?> = ArrayList()
        var resultType: ResultType? = null
        if (track != null) {
            track.setResultDetails(ResultDetails.LOCALIZED_DNS)
        }
        var clientGeolocation: Geolocation? = null
        val networkNode: NetworkNode? = getNetworkNode(request.getClientIP())
        if (networkNode != null && networkNode.getGeolocation() != null) {
            clientGeolocation = networkNode.getGeolocation()
            resultType = ResultType.CZ
        } else {
            clientGeolocation = getClientGeolocation(request.getClientIP(), track, ds)
            resultType = ResultType.GEO
        }
        if (clientGeolocation == null) {
            result.addAll(selectTrafficRoutersMiss(request.getZoneName(), ds))
            resultType = ResultType.MISS
        } else {
            result.addAll(
                selectTrafficRoutersLocalized(
                    clientGeolocation,
                    request.getZoneName(),
                    ds,
                    track,
                    request.getQueryType()
                )
            )
            if (track != null) {
                track.setClientGeolocation(clientGeolocation)
            }
        }
        if (track != null) {
            track.setResult(resultType)
        }
        return result
    }

    @Throws(GeolocationException::class)
    fun selectTrafficRoutersMiss(zoneName: String?, ds: DeliveryService?): MutableList<InetRecord?> {
        val trafficRouterRecords: MutableList<InetRecord?> = ArrayList()
        if (!isEdgeDNSRouting && !isEdgeHTTPRouting) {
            return trafficRouterRecords
        }
        val trafficRouterLocations: List<TrafficRouterLocation?>? = cacheRegister!!.getEdgeTrafficRouterLocations()
        val edgeTrafficRouters: MutableList<Node?> = ArrayList()
        val orderedNodes: MutableMap<String?, List<Node?>?> = HashMap()
        var limit: Int =
            if ((edgeDNSRoutingLimit > getEdgeHTTPRoutingLimit(ds))) edgeDNSRoutingLimit else getEdgeHTTPRoutingLimit(ds)
        var index: Int = 0
        var exhausted: Boolean = false

        // if limits don't exist, or do exist and are higher than the number of edge TRs, use the number of edge TRs as the limit
        if (limit == 0 || limit > cacheRegister.getEdgeTrafficRouterCount()) {
            limit = cacheRegister.getEdgeTrafficRouterCount()
        }

        // grab one TR per location until the limit is reached
        while (edgeTrafficRouters.size < limit && !exhausted) {
            val initialCount: Int = edgeTrafficRouters.size
            for (location: TrafficRouterLocation? in trafficRouterLocations!!) {
                if (edgeTrafficRouters.size >= limit) {
                    break
                }
                if (!orderedNodes.containsKey(location.getId())) {
                    orderedNodes.put(
                        location.getId(), consistentHasher.selectHashables(
                            location!!.getTrafficRouters(), zoneName
                        )
                    )
                }
                val trafficRouters: List<Node?>? = orderedNodes.get(location.getId())
                if ((trafficRouters == null) || trafficRouters.isEmpty() || (index >= trafficRouters.size)) {
                    continue
                }
                edgeTrafficRouters.add(trafficRouters.get(index))
            }

            /*
			 * we iterated through every location and attempted to add edge TR at index, but none were added....
			 * normally, these values would never match unless we ran out of options...
			 * if so, we've exhausted our options so we need to break out of the while loop
			 */if (initialCount == edgeTrafficRouters.size) {
                exhausted = true
            }
            index++
        }
        if (!edgeTrafficRouters.isEmpty()) {
            if (isEdgeDNSRouting) {
                trafficRouterRecords.addAll(nsRecordsFromNodes(ds, edgeTrafficRouters))
            }
            if ((ds != null) && !ds.isDns() && isEdgeHTTPRouting) { // only generate edge routing records for HTTP DSs when necessary
                trafficRouterRecords.addAll(inetRecordsFromNodes(ds, edgeTrafficRouters))
            }
        }
        return trafficRouterRecords
    }

    @Throws(GeolocationException::class)
    fun selectTrafficRoutersLocalized(
        clientGeolocation: Geolocation?,
        name: String?,
        ds: DeliveryService?
    ): MutableList<InetRecord?> {
        return selectTrafficRoutersLocalized(clientGeolocation, name, ds, null, 0)
    }

    @Throws(GeolocationException::class)
    fun selectTrafficRoutersLocalized(
        clientGeolocation: Geolocation?,
        zoneName: String?,
        ds: DeliveryService?,
        track: StatTracker.Track?,
        queryType: Int
    ): MutableList<InetRecord?> {
        val trafficRouterRecords: MutableList<InetRecord?> = ArrayList()
        if (!isEdgeDNSRouting && !isEdgeHTTPRouting) {
            return trafficRouterRecords
        }
        val trafficRouterLocations: List<TrafficRouterLocation?>? = orderLocations(
            cacheRegister!!.getEdgeTrafficRouterLocations(),
            clientGeolocation
        ) as List<TrafficRouterLocation?>?
        for (location: TrafficRouterLocation? in trafficRouterLocations!!) {
            val trafficRouters: List<Node?>? = consistentHasher.selectHashables(
                location!!.getTrafficRouters(), zoneName
            )
            if (trafficRouters == null || trafficRouters.isEmpty()) {
                continue
            }
            if (isEdgeDNSRouting) {
                trafficRouterRecords.addAll(nsRecordsFromNodes(ds, trafficRouters))
            }
            if ((ds != null) && !ds.isDns() && isEdgeHTTPRouting) { // only generate edge routing records for HTTP DSs when necessary
                trafficRouterRecords.addAll(inetRecordsFromNodes(ds, trafficRouters))
            }
            if (track != null) {
                track.setResultLocation(location.getGeolocation())
            }
            break
        }
        return trafficRouterRecords
    }

    @Throws(GeolocationException::class)
    private fun getEdgeCaches(request: DNSRequest, ds: DeliveryService?, track: StatTracker.Track): DNSRouteResult? {
        val result: DNSRouteResult = DNSRouteResult()
        result.setDeliveryService(ds)
        if (ds == null) {
            track.setResult(ResultType.STATIC_ROUTE)
            track.setResultDetails(ResultDetails.DS_NOT_FOUND)
            return null
        }
        if (!ds.isAvailable()) {
            result.setAddresses(ds.getFailureDnsResponse(request, track))
            result.addAddresses(selectTrafficRouters(request, ds))
            return result
        }
        val requestVersion: IPVersions =
            if (request.getQueryType() == Type.AAAA) IPVersions.IPV6ONLY else IPVersions.IPV4ONLY
        val cacheLocation: CacheLocation? =
            getCoverageZoneCacheLocation(request.getClientIP(), ds, false, track, requestVersion)
        var caches: MutableList<Cache?>? = selectCachesByCZ(ds, cacheLocation, track, requestVersion)
        if (caches != null) {
            track.setResult(ResultType.CZ)
            track.setClientGeolocation(cacheLocation.getGeolocation())
            result.setAddresses(inetRecordsFromCaches(ds, caches, request))
            result.addAddresses(selectTrafficRouters(request, ds))
            return result
        }
        if (ds.isCoverageZoneOnly()) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_CZ_ONLY)
            result.setAddresses(ds.getFailureDnsResponse(request, track))
            result.addAddresses(selectTrafficRouters(request, ds))
            return result
        }
        try {
            val inetRecords: MutableList<InetRecord?>? = federationRegistry!!.findInetRecords(
                ds.getId(),
                CidrAddress.Companion.fromString(request.getClientIP())
            )
            if (inetRecords != null && !inetRecords.isEmpty()) {
                result.setAddresses(inetRecords)
                track.setResult(ResultType.FED)
                return result
            }
        } catch (e: NetworkNodeException) {
            LOGGER.error("Bad client address: '" + request.getClientIP() + "'")
        }
        if (track.continueGeo) {
            caches = selectCachesByGeo(request.getClientIP(), ds, cacheLocation, track, requestVersion)
        }
        if (caches != null) {
            track.setResult(ResultType.GEO)
            result.setAddresses(inetRecordsFromCaches(ds, caches, request))
        } else {
            track.setResult(ResultType.MISS)
            result.setAddresses(ds.getFailureDnsResponse(request, track))
        }
        result.addAddresses(selectTrafficRouters(request, ds))
        return result
    }

    private fun nsRecordsFromNodes(ds: DeliveryService?, nodes: List<Node?>): List<InetRecord?> {
        val nsRecords: MutableList<InetRecord?> = ArrayList()
        val limit: Int = if ((edgeDNSRoutingLimit > nodes.size)) nodes.size else edgeDNSRoutingLimit
        var ttl: Long = edgeNSttl
        if (ds != null && ds.getTtls().has("NS")) {
            ttl = optLong(ds.getTtls(), "NS") // no exception
        }
        for (i in 0 until limit) {
            val node: Node? = nodes.get(i)
            nsRecords.add(InetRecord(node.getFqdn(), ttl, Type.NS))
        }
        return nsRecords
    }

    fun inetRecordsFromNodes(ds: DeliveryService?, nodes: List<Node?>): List<InetRecord?> {
        val addresses: MutableList<InetRecord?> = ArrayList()
        val limit: Int = if ((getEdgeHTTPRoutingLimit(ds) > nodes.size)) nodes.size else getEdgeHTTPRoutingLimit(ds)
        if (ds == null) {
            return addresses
        }
        val ttls: JsonNode? = ds.getTtls()
        for (i in 0 until limit) {
            val node: Node? = nodes.get(i)
            if (node.getIp4() != null) {
                addresses.add(InetRecord(node.getIp4(), optLong(ttls, "A")))
            }
            if (node.getIp6() != null && ds.isIp6RoutingEnabled()) {
                addresses.add(InetRecord(node.getIp6(), optLong(ttls, "AAAA")))
            }
        }
        return addresses
    }

    /**
     * Extracts the IP Addresses from a set of caches based on a Delivery Service's configuration
     * @param ds The Delivery Service being served. If this DS does not have "IPv6 routing enabled",
     * then the IPAddresses returned will not include IPv6 addresses.
     * @param caches The list of caches chosen to serve ds. If the length of this list is greater
     * than the maximum allowed IP addresses in a DNS response by the
     * [DeliveryService.getMaxDnsIps] of the requested Delivery Service, the maximum
     * allowed number will be chosen from the list at random.
     * @param request The request being served - used for consistent hashing when caches must be
     * chosen at random
     * @return The IP Addresses of the passed caches. In general, these may be IPv4 or IPv6.
     */
    fun inetRecordsFromCaches(
        ds: DeliveryService,
        caches: MutableList<Cache?>,
        request: Request
    ): MutableList<InetRecord?> {
        val addresses: MutableList<InetRecord?> = ArrayList()
        val maxDnsIps: Int = ds.getMaxDnsIps()
        val selectedCaches: MutableList<Cache?>?
        if (maxDnsIps > 0 && isConsistentDNSRouting) { // only consistent hash if we must
            selectedCaches = consistentHasher.selectHashables(caches, ds.getDispersion(), request.getHostname())
        } else if (maxDnsIps > 0) {
            /*
			 * We also shuffle in NameServer when adding Records to the Message prior
			 * to sending it out, as the Records are sorted later when we fill the
			 * dynamic zone if DNSSEC is enabled. We shuffle here prior to pruning
			 * for maxDnsIps so that we ensure we are spreading load across all caches
			 * assigned to this delivery service.
			*/
            Collections.shuffle(caches, random)
            selectedCaches = ArrayList()
            for (cache: Cache? in caches) {
                selectedCaches.add(cache)
                if (selectedCaches.size >= maxDnsIps) {
                    break
                }
            }
        } else {
            selectedCaches = caches
        }
        for (cache: Cache? in selectedCaches!!) {
            addresses.addAll((cache!!.getIpAddresses(ds.getTtls(), ds.isIp6RoutingEnabled()))!!)
        }
        return addresses
    }

    /**
     * Geo-locates the client based on their IP address and the Delivery Service they requested.
     *
     *
     * This is optimized over [.getLocation] because
     * @param clientIp The IP Address of the requesting client.
     * @param track A state-tracking object, it will be notified of the calculated client location
     * for optimization of future queries.
     * @param deliveryService The Delivery Service being served. Currently only used for logging
     * error information.
     * @return The client's calculated geographic location
     * @throws GeolocationException
     */
    @Throws(GeolocationException::class)
    fun getClientGeolocation(
        clientIp: String?,
        track: StatTracker.Track?,
        deliveryService: DeliveryService?
    ): Geolocation? {
        if (track != null && track.isClientGeolocationQueried()) {
            return track.getClientGeolocation()
        }
        val clientGeolocation: Geolocation
        if (deliveryService != null) {
            clientGeolocation = getLocation(clientIp, deliveryService)
        } else {
            clientGeolocation = getLocation(clientIp)
        }
        if (track != null) {
            track.setClientGeolocation(clientGeolocation)
            track.setClientGeolocationQueried(true)
        }
        return clientGeolocation
    }

    /**
     * Geo-locates the client based on their IP address and the Delivery Service they requested.
     * @param clientIp The IP Address of the requesting client.
     * @param ds The Delivery Service being served. If the client's location is blocked by this
     * Delivery Service, the returned location will instead be the appropriate fallback/miss
     * location.
     * @param cacheLocation If this is not 'null', its location will be used in lieu of calculating
     * one for the client.
     * @return The client's calculated geographic location (or the appropriate fallback/miss
     * location).
     */
    @Throws(GeolocationException::class)
    fun getClientLocation(
        clientIp: String?,
        ds: DeliveryService?,
        cacheLocation: Location?,
        track: StatTracker.Track?
    ): Geolocation? {
        if (cacheLocation != null) {
            return cacheLocation.getGeolocation()
        }
        val clientGeolocation: Geolocation? = getClientGeolocation(clientIp, track, ds)
        return ds!!.supportLocation(clientGeolocation)
    }

    /**
     * Selects caches to service requests for a Delivery Service from a cache location based on
     * Coverage Zone configuration.
     *
     *
     * This is equivalent to calling [.selectCachesByCZ]
     * with a 'null' "track" argument.
     *
     * @param ds The Delivery Service being served.
     * @param cacheLocation The location from which caches will be selected.
     * @return All of the caches in the given location capable of serving ds.
     */
    fun selectCachesByCZ(
        ds: DeliveryService?,
        cacheLocation: CacheLocation?,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        return selectCachesByCZ(ds, cacheLocation, null, requestVersion)
    }

    /**
     * Selects caches to service requests for a Delivery Service from a cache location based on
     * Coverage Zone Configuration.
     * @param deliveryServiceId An identifier for the [DeliveryService] being served.
     * @param cacheLocationId An identifier for the [CacheLocation] from which caches will be
     * selected.
     * @return All of the caches in the given location capable of serving the identified Delivery
     * Service.
     */
    fun selectCachesByCZ(
        deliveryServiceId: String?,
        cacheLocationId: String?,
        track: StatTracker.Track?,
        requestVersion: IPVersions
    ): List<Cache?>? {
        return selectCachesByCZ(
            cacheRegister!!.getDeliveryService(deliveryServiceId),
            cacheRegister.getCacheLocation(cacheLocationId),
            track,
            requestVersion
        )
    }

    /**
     * Selects caches to service requests for a Delivery Service from a cache location based on
     * Coverage Zone Configuration.
     *
     *
     * This is equivalent to calling [.selectCachesByCZ]
     * with the "result" argument set to [ResultType.CZ].
     *
     * @param ds The Delivery Service being served.
     * @param cacheLocation The location from which caches will be selected
     * @return All of the caches in the given location capable of serving ds.
     */
    private fun selectCachesByCZ(
        ds: DeliveryService?,
        cacheLocation: CacheLocation?,
        track: StatTracker.Track?,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        return selectCachesByCZ(
            ds,
            cacheLocation,
            track,
            ResultType.CZ,
            requestVersion
        ) // ResultType.CZ was the original default before DDC
    }

    /**
     * Selects caches to service requests for a Delivery Service from a cache location based on
     * Coverage Zone Configuration.
     *
     *
     * Obviously, at this point, the location from which to select caches must already be known.
     * So it's totally possible that that decision wasn't made based on Coverage Zones at all,
     * that's just the default routing result chosen by a common caller of this method
     * ([.selectCachesByCZ]).
     *
     * @param ds The Delivery Service being served.
     * @param cacheLocation The location from which caches will be selected.
     * @param result The type of routing result that resulted in the returned caches being selected.
     * This is used for tracking routing results.
     * @return All of the caches in the given location capable of serving ds.
     */
    private fun selectCachesByCZ(
        ds: DeliveryService?,
        cacheLocation: CacheLocation?,
        track: StatTracker.Track?,
        result: ResultType,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        if ((cacheLocation == null) || (ds == null) || !ds.isLocationAvailable(cacheLocation)) {
            return null
        }
        val caches: MutableList<Cache?>? = selectCaches(cacheLocation, ds, requestVersion)
        if (caches != null && track != null) {
            track.setResult(result)
            if (track.isFromBackupCzGroup()) {
                track.setResultDetails(ResultDetails.DS_CZ_BACKUP_CG)
            }
            track.setResultLocation(cacheLocation.getGeolocation())
        }
        return caches
    }

    /**
     * Gets multiple routes for STEERING Delivery Services
     *
     * @param request The client's HTTP Request
     * @param track A [Track] object used to track routing statistics
     * @return The list of routes available to service the client's request.
     */
    @Throws(MalformedURLException::class, GeolocationException::class)
    fun multiRoute(request: HTTPRequest, track: StatTracker.Track): HTTPRouteResult? {
        val entryDeliveryService: DeliveryService? = cacheRegister!!.getDeliveryService(request)
        val steeringResults: MutableList<SteeringResult>? = getSteeringResults(request, track, entryDeliveryService)
        if (steeringResults == null) {
            return null
        }
        val routeResult: HTTPRouteResult = HTTPRouteResult(true)
        routeResult.setDeliveryService(entryDeliveryService)
        if (entryDeliveryService!!.isRegionalGeoEnabled()) {
            enforce(this, request, entryDeliveryService, null, routeResult, track)
            if (routeResult.getUrl() != null) {
                return routeResult
            }
        }
        val resultsToRemove: MutableList<SteeringResult> = ArrayList()
        val selectedCaches: MutableSet<Cache?> = HashSet()

        // Pattern based consistent hashing - use consistentHashRegex from steering DS instead of targets
        val steeringHash: String? =
            buildPatternBasedHashString(entryDeliveryService.getConsistentHashRegex(), request.getPath())
        for (steeringResult: SteeringResult in steeringResults) {
            val ds: DeliveryService? = steeringResult.getDeliveryService()
            var caches: List<Cache?>? = selectCaches(request, ds, track)

            // child Delivery Services can use their query parameters
            val pathToHash: String = steeringHash + ds!!.extractSignificantQueryParams(request)
            if (caches != null && !caches.isEmpty()) {
                if (isClientSteeringDiversityEnabled) {
                    var tryCaches: MutableList<Cache?>? = ArrayList(caches)
                    tryCaches!!.removeAll(selectedCaches)
                    if (!tryCaches.isEmpty()) {
                        caches = tryCaches
                    } else if (track.result == ResultType.DEEP_CZ) {
                        // deep caches have been selected already, try non-deep selection
                        tryCaches = selectCaches(request, ds, track, false)
                        track.setResult(ResultType.DEEP_CZ) // request should still be tracked as a DEEP_CZ hit
                        tryCaches!!.removeAll(selectedCaches)
                        if (!tryCaches.isEmpty()) {
                            caches = tryCaches
                        }
                    }
                }
                val cache: Cache? = consistentHasher.selectHashable(caches, ds.getDispersion(), pathToHash)
                steeringResult.setCache(cache)
                selectedCaches.add(cache)
            } else {
                resultsToRemove.add(steeringResult)
            }
        }
        steeringResults.removeAll(resultsToRemove)
        geoSortSteeringResults(steeringResults, request.getClientIP(), entryDeliveryService)
        for (steeringResult: SteeringResult in steeringResults) {
            routeResult.addUrl(
                URL(
                    steeringResult.getDeliveryService().createURIString(request, steeringResult.getCache())
                )
            )
        }
        if (routeResult.getUrls().isEmpty()) {
            routeResult.addUrl(entryDeliveryService.getFailureHttpResponse(request, track))
        }
        return routeResult
    }

    /**
     * Creates a string to be used in consistent hashing.
     *
     *
     * This uses simply the request path by default, but will consider any and all Query Parameters
     * that are in deliveryService's [DeliveryService] consistentHashQueryParam set as well.
     * It will also fall back on the request path if the query parameters are not UTF-8-encoded.
     *
     * @param deliveryService The [DeliveryService] being requested
     * @param request An [HTTPRequest] representing the client's request.
     * @return A string appropriate to use for consistent hashing to service the request
     */
    fun buildPatternBasedHashString(deliveryService: DeliveryService?, request: HTTPRequest): String {
        val requestPath: String? = request.getPath()
        val hashString: StringBuilder = StringBuilder("")
        if (deliveryService.getConsistentHashRegex() != null && !requestPath!!.isEmpty()) {
            hashString.append(buildPatternBasedHashString(deliveryService.getConsistentHashRegex(), requestPath))
        }
        hashString.append(deliveryService!!.extractSignificantQueryParams(request))
        return hashString.toString()
    }

    /**
     * Constructs a string to be used in consistent hashing
     *
     *
     * If `regex` is `null` or empty - or if an error occurs applying it -, returns
     * `requestPath` unaltered.
     *
     * @param regex A regular expression matched against the client's request path to extract
     * information important to consistent hashing
     * @param requestPath The client's request path - e.g. `/some/path` from
     * `https://example.com/some/path`
     * @return The parts of requestPath that matched regex
     */
    fun buildPatternBasedHashString(regex: String?, requestPath: String?): String? {
        if (regex == null || regex.isEmpty()) {
            return requestPath
        }
        try {
            val pattern: Pattern = Pattern.compile(regex)
            val matcher: Matcher = pattern.matcher(requestPath)
            val sb: StringBuilder = StringBuilder("")
            if (matcher.find() && matcher.groupCount() > 0) {
                for (i in 1..matcher.groupCount()) {
                    val text: String = matcher.group(i)
                    sb.append(text)
                }
                return sb.toString()
            }
        } catch (e: Exception) {
            val error: StringBuilder = StringBuilder("Failed to construct hash string using regular expression: '")
            error.append(regex)
            error.append("' against request path: '")
            error.append(requestPath)
            error.append("' Exception: ")
            error.append(e.toString())
            LOGGER.error(error.toString())
        }
        return requestPath
    }

    /**
     * Routes an HTTP request.
     * @param request The request being routed.
     * @return The result of routing the HTTP request.
     * @throws MalformedURLException
     * @throws GeolocationException
     */
    @Throws(MalformedURLException::class, GeolocationException::class)
    fun route(request: HTTPRequest, track: StatTracker.Track): HTTPRouteResult? {
        track.setRouteType(RouteType.HTTP, request.getHostname())
        if (isMultiRouteRequest(request)) {
            return multiRoute(request, track)
        } else {
            return singleRoute(request, track)
        }
    }

    /**
     * Routes an HTTP request that isn't for a CLIENT_STEERING-type Delivery Service.
     * @param request The request being routed.
     * @return The result of routing this HTTP request.
     * @throws MalformedURLException if a URL cannot be constructed to return to the client
     */
    @Throws(MalformedURLException::class, GeolocationException::class)
    fun singleRoute(request: HTTPRequest, track: StatTracker.Track): HTTPRouteResult? {
        val deliveryService: DeliveryService? = getDeliveryService(request, track)
        if (deliveryService == null) {
            return null
        }
        val routeResult: HTTPRouteResult = HTTPRouteResult(false)
        if (!deliveryService.isAvailable()) {
            routeResult.setUrl(deliveryService.getFailureHttpResponse(request, track))
            return routeResult
        }
        routeResult.setDeliveryService(deliveryService)
        val caches: List<Cache?>? = selectCaches(request, deliveryService, track)
        if (caches == null || caches.isEmpty()) {
            if (track.getResult() == ResultType.GEO_REDIRECT) {
                routeResult.setUrl(URL(deliveryService.getGeoRedirectUrl()))
                LOGGER.debug(
                    String.format(
                        "NGB redirect to url: %s for request: %s",
                        deliveryService.getGeoRedirectUrl(),
                        request.getRequestedUrl()
                    )
                )
                return routeResult
            }
            routeResult.setUrl(deliveryService.getFailureHttpResponse(request, track))
            return routeResult
        }

        // Pattern based consistent hashing
        val pathToHash: String = buildPatternBasedHashString(deliveryService, request)
        val cache: Cache? = consistentHasher.selectHashable(caches, deliveryService.getDispersion(), pathToHash)

        // Enforce anonymous IP blocking if a DS has anonymous blocking enabled
        // and the feature is enabled
        if (deliveryService.isAnonymousIpEnabled() && AnonymousIp.Companion.getCurrentConfig().enabled) {
            AnonymousIp.Companion.enforce(this, request, deliveryService, cache, routeResult, track)
            if (routeResult.getResponseCode() == AnonymousIp.Companion.BLOCK_CODE) {
                return routeResult
            }
        }
        if (deliveryService.isRegionalGeoEnabled()) {
            enforce(this, request, deliveryService, cache, routeResult, track)
            return routeResult
        }
        val uriString: String? = deliveryService.createURIString(request, cache)
        routeResult.setUrl(URL(uriString))
        return routeResult
    }

    /**
     * Gets all the possible steering results for a request to a Delivery Service.
     * @param request The client HTTP request.
     * @param entryDeliveryService The steering Delivery Service being served.
     * @return All of the possible steering results for routing request through entryDeliveryService.
     */
    private fun getSteeringResults(
        request: HTTPRequest,
        track: StatTracker.Track,
        entryDeliveryService: DeliveryService?
    ): MutableList<SteeringResult>? {
        if (isTlsMismatch(request, entryDeliveryService)) {
            track.setResult(ResultType.ERROR)
            track.setResultDetails(ResultDetails.DS_TLS_MISMATCH)
            return null
        }
        val steeringResults: MutableList<SteeringResult>? =
            consistentHashMultiDeliveryService(entryDeliveryService, request)
        if (steeringResults == null || steeringResults.isEmpty()) {
            track.setResult(ResultType.DS_MISS)
            track.setResultDetails(ResultDetails.DS_NOT_FOUND)
            return null
        }
        val toBeRemoved: MutableList<SteeringResult> = ArrayList()
        for (steeringResult: SteeringResult in steeringResults) {
            val ds: DeliveryService? = steeringResult.getDeliveryService()
            if (isTlsMismatch(request, ds)) {
                track.setResult(ResultType.ERROR)
                track.setResultDetails(ResultDetails.DS_TLS_MISMATCH)
                return null
            }
            if (!ds!!.isAvailable()) {
                toBeRemoved.add(steeringResult)
            }
        }
        steeringResults.removeAll(toBeRemoved)
        return if (steeringResults.isEmpty()) null else steeringResults
    }

    /**
     * Gets the Delivery Service that matches the client HTTP request.
     * @param request The client HTTP request.
     * @return The Delivery Service corresponding to the request if one can be found, otherwise
     * `null`.
     */
    private fun getDeliveryService(request: HTTPRequest, track: StatTracker.Track): DeliveryService? {
        val xtcSteeringOption: String? = request.getHeaderValue(XTC_STEERING_OPTION)
        val deliveryService: DeliveryService? =
            consistentHashDeliveryService(cacheRegister!!.getDeliveryService(request), request, xtcSteeringOption)
        if (deliveryService == null) {
            track.setResult(ResultType.DS_MISS)
            track.setResultDetails(ResultDetails.DS_NOT_FOUND)
            return null
        }
        if (isTlsMismatch(request, deliveryService)) {
            track.setResult(ResultType.ERROR)
            track.setResultDetails(ResultDetails.DS_TLS_MISMATCH)
            return null
        }
        return deliveryService
    }

    /**
     * Checks if the TLS settings on the client HTTP request match those of the Delivery Service
     * it's requesting.
     * @param request The client HTTP request.
     * @param deliveryService The Delivery Service being served.
     */
    private fun isTlsMismatch(request: HTTPRequest, deliveryService: DeliveryService?): Boolean {
        if (request.isSecure() && !deliveryService!!.isSslEnabled()) {
            return true
        }
        if (!request.isSecure() && !deliveryService!!.isAcceptHttp()) {
            return true
        }
        return false
    }

    /**
     * Finds a network subnet for the given IP address based on Deep Coverage Zone configuration.
     * @param ip The IP address to look up.
     * @return A network subnet  capable of serving requests for the given IP, or `null` if
     * one couldn't be found.
     */
    protected fun getDeepNetworkNode(ip: String?): NetworkNode? {
        try {
            return NetworkNode.Companion.getDeepInstance()!!.getNetwork(ip)
        } catch (e: NetworkNodeException) {
            LOGGER.warn(e)
        }
        return null
    }

    /**
     * Finds a network subnet for the given IP address based on Coverage Zone configuration.
     * @param ip The IP address to look up.
     * @return A network subnet capable of serving requests for the given IP, or `null` if
     * one couldn't be found.
     */
    protected fun getNetworkNode(ip: String?): NetworkNode? {
        try {
            return NetworkNode.Companion.getInstance()!!.getNetwork(ip)
        } catch (e: NetworkNodeException) {
            LOGGER.warn(e)
        }
        return null
    }

    fun getCoverageZoneCacheLocation(
        ip: String?,
        deliveryServiceId: String?,
        requestVersion: IPVersions?
    ): CacheLocation? {
        return getCoverageZoneCacheLocation(ip, deliveryServiceId, false, null, requestVersion) // default is not deep
    }

    /**
     * Finds the deep coverage zone location information for a give IP address.
     * @param ip
     * @return deep coverage zone location
     */
    fun getDeepCoverageZoneLocationByIP(ip: String?): CacheLocation? {
        val networkNode: NetworkNode? = getDeepNetworkNode(ip)
        if (networkNode == null) {
            return null
        }
        val cacheLocation: CacheLocation? = networkNode.getLocation() as CacheLocation?
        if (cacheLocation != null) {
            cacheLocation.loadDeepCaches(networkNode.getDeepCacheNames(), cacheRegister)
        }
        return cacheLocation
    }

    fun getCoverageZoneCacheLocation(
        ip: String?,
        deliveryServiceId: String?,
        useDeep: Boolean,
        track: StatTracker.Track?,
        requestVersion: IPVersions?
    ): CacheLocation? {
        val networkNode: NetworkNode? = if (useDeep) getDeepNetworkNode(ip) else getNetworkNode(ip)
        val localizationMethod: LocalizationMethod = if (useDeep) LocalizationMethod.DEEP_CZ else LocalizationMethod.CZ
        if (networkNode == null) {
            return null
        }
        val deliveryService: DeliveryService? = cacheRegister!!.getDeliveryService(deliveryServiceId)
        var cacheLocation: CacheLocation? = networkNode.getLocation() as CacheLocation?
        if (useDeep && cacheLocation != null) {
            // lazily load deep Caches into the deep CacheLocation
            cacheLocation.loadDeepCaches(networkNode.getDeepCacheNames(), cacheRegister)
        }
        if (cacheLocation != null && !cacheLocation.isEnabledFor(localizationMethod)) {
            return null
        }
        if (cacheLocation != null && !getSupportingCaches(
                cacheLocation.getCaches(),
                deliveryService,
                requestVersion
            ).isEmpty()
        ) {
            return cacheLocation
        }
        if (useDeep) {
            // there were no available deep caches in the deep CZF
            return null
        }
        if (networkNode.getLoc() == null) {
            return null
        }

        // find CacheLocation
        cacheLocation = cacheRegister.getCacheLocationById(networkNode.getLoc())
        if (cacheLocation != null && !cacheLocation.isEnabledFor(localizationMethod)) {
            track!!.continueGeo =
                false // hit in the CZF but the cachegroup doesn't allow CZ-localization, don't fall back to GEO
            return null
        }
        if (cacheLocation != null && !getSupportingCaches(
                cacheLocation.getCaches(),
                deliveryService,
                requestVersion
            ).isEmpty()
        ) {
            // lazy loading in case a CacheLocation has not yet been associated with this NetworkNode
            networkNode.setLocation(cacheLocation)
            return cacheLocation
        }
        if (cacheLocation != null && cacheLocation.getBackupCacheGroups() != null) {
            for (cacheGroup: String? in cacheLocation.getBackupCacheGroups()) {
                val bkCacheLocation: CacheLocation? = cacheRegister.getCacheLocationById(cacheGroup)
                if (bkCacheLocation != null && !bkCacheLocation.isEnabledFor(localizationMethod)) {
                    continue
                }
                if (bkCacheLocation != null && !getSupportingCaches(
                        bkCacheLocation.getCaches(),
                        deliveryService,
                        requestVersion
                    ).isEmpty()
                ) {
                    LOGGER.debug("Got backup CZ cache group " + bkCacheLocation.getId() + " for " + ip + ", ds " + deliveryServiceId)
                    if (track != null) {
                        track.setFromBackupCzGroup(true)
                    }
                    return bkCacheLocation
                }
            }
            // track.continueGeo
            // will become to false only when backups are configured and (primary group's) fallbackToClosedGeo is configured (non-empty list) to false
            // False signals subsequent cacheSelection routine to stop geo based selection.
            if (!cacheLocation.isUseClosestGeoLoc()) {
                track!!.continueGeo = false
                return null
            }
        }

        // We had a hit in the CZF but the name does not match a known cache location.
        // Check whether the CZF entry has a geolocation and use it if so.
        var availableLocations: List<CacheLocation?>? = cacheRegister.filterAvailableCacheLocations(deliveryServiceId)
        availableLocations = filterEnabledLocations(availableLocations, localizationMethod)
        val closestCacheLocation: CacheLocation? = getClosestCacheLocation(
            availableLocations,
            networkNode.getGeolocation(),
            cacheRegister.getDeliveryService(deliveryServiceId),
            requestVersion
        )
        if (closestCacheLocation != null) {
            LOGGER.debug("Got closest CZ cache group " + closestCacheLocation.getId() + " for " + ip + ", ds " + deliveryServiceId)
            if (track != null) {
                track.setFromBackupCzGroup(true)
            }
        }
        return closestCacheLocation
    }

    fun filterEnabledLocations(
        locations: Collection<CacheLocation?>?,
        localizationMethod: LocalizationMethod?
    ): List<CacheLocation?> {
        return locations!!.stream()
            .filter(Predicate({ loc: CacheLocation? -> loc!!.isEnabledFor(localizationMethod) }))
            .collect(Collectors.toList())
    }

    fun getDeepCoverageZoneCacheLocation(
        ip: String?,
        deliveryService: DeliveryService?,
        requestVersion: IPVersions?
    ): CacheLocation? {
        return getCoverageZoneCacheLocation(ip, deliveryService, true, null, requestVersion)
    }

    fun getCoverageZoneCacheLocation(
        ip: String?,
        deliveryService: DeliveryService?,
        useDeep: Boolean,
        track: StatTracker.Track?,
        requestVersion: IPVersions?
    ): CacheLocation? {
        return getCoverageZoneCacheLocation(ip, deliveryService.getId(), useDeep, track, requestVersion)
    }

    fun getCoverageZoneCacheLocation(
        ip: String?,
        deliveryService: DeliveryService?,
        requestVersion: IPVersions?
    ): CacheLocation? {
        return getCoverageZoneCacheLocation(ip, deliveryService.getId(), requestVersion)
    }
    /**
     * Chooses a cache for a Delivery Service based on the Coverage Zone File or Deep Coverage Zone
     * File given a client's IP and request *path*.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param requestPath The client's requested path - e.g.
     * `http://test.example.com/request/path`  `/request/path`
     * @param useDeep if `true` will attempt to use Deep Coverage Zones - otherwise will only
     * use Coverage Zone File
     * @return A [Cache] object chosen to serve the client's request
     */
    /**
     * Chooses a [Cache] for a Delivery Service based on the Coverage Zone File given a
     * client's IP and request *path*.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param requestPath The client's requested path - e.g.
     * `http://test.example.com/request/path`  `/request/path`
     * @return A cache object chosen to serve the client's request
     */
    @JvmOverloads
    fun consistentHashForCoverageZone(
        ip: String,
        deliveryServiceId: String,
        requestPath: String?,
        useDeep: Boolean = false
    ): Cache? {
        val r: HTTPRequest = HTTPRequest()
        r.setPath(requestPath)
        r.setQueryString("")
        return consistentHashForCoverageZone(ip, deliveryServiceId, r, useDeep)
    }

    /**
     * Chooses a cache for a Delivery Service based on the Coverage Zone File or Deep Coverage Zone
     * File given a client's IP and request.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param request The client's HTTP request
     * @param useDeep if `true` will attempt to use Deep Coverage Zones - otherwise will only
     * use Coverage Zone File
     * @return A [Cache] object chosen to serve the client's request
     */
    fun consistentHashForCoverageZone(
        ip: String,
        deliveryServiceId: String,
        request: HTTPRequest,
        useDeep: Boolean
    ): Cache? {
        val deliveryService: DeliveryService? = cacheRegister!!.getDeliveryService(deliveryServiceId)
        if (deliveryService == null) {
            LOGGER.error("Failed getting delivery service from cache register for id '" + deliveryServiceId + "'")
            return null
        }
        val requestVersion: IPVersions = if (ip.contains(":")) IPVersions.IPV6ONLY else IPVersions.IPV4ONLY
        val coverageZoneCacheLocation: CacheLocation? =
            getCoverageZoneCacheLocation(ip, deliveryService, useDeep, null, requestVersion)
        val caches: List<Cache?>? = selectCachesByCZ(deliveryService, coverageZoneCacheLocation, requestVersion)
        if (caches == null || caches.isEmpty()) {
            return null
        }
        val pathToHash: String = buildPatternBasedHashString(deliveryService, request)
        return consistentHasher.selectHashable(caches, deliveryService.getDispersion(), pathToHash)
    }

    /**
     * Chooses a [Cache] for a Delivery Service based on GeoLocation given a client's IP and
     * request *path*.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param requestPath The client's requested path - e.g.
     * `http://test.example.com/request/path`  `/request/path`
     * @return A cache object chosen to serve the client's request
     */
    fun consistentHashForGeolocation(ip: String, deliveryServiceId: String, requestPath: String?): Cache? {
        val r: HTTPRequest = HTTPRequest()
        r.setPath(requestPath)
        r.setQueryString("")
        return consistentHashForGeolocation(ip, deliveryServiceId, r)
    }

    /**
     * Chooses a [Cache] for a Delivery Service based on GeoLocation given a client's IP and
     * request.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param request The client's HTTP request
     * @return A cache object chosen to serve the client's request
     */
    fun consistentHashForGeolocation(ip: String, deliveryServiceId: String, request: HTTPRequest): Cache? {
        val deliveryService: DeliveryService? = cacheRegister!!.getDeliveryService(deliveryServiceId)
        if (deliveryService == null) {
            LOGGER.error("Failed getting delivery service from cache register for id '" + deliveryServiceId + "'")
            return null
        }
        val requestVersion: IPVersions = if (ip.contains(":")) IPVersions.IPV6ONLY else IPVersions.IPV4ONLY
        var caches: List<Cache?>? = null
        if (deliveryService.isCoverageZoneOnly() && deliveryService.getGeoRedirectUrl() != null) {
            //use the NGB redirect
            caches = enforceGeoRedirect(StatTracker.Companion.getTrack(), deliveryService, ip, null, requestVersion)
        } else {
            val cacheLocation: CacheLocation? = getCoverageZoneCacheLocation(ip, deliveryServiceId, requestVersion)
            try {
                caches = selectCachesByGeo(
                    ip,
                    deliveryService,
                    cacheLocation,
                    StatTracker.Companion.getTrack(),
                    requestVersion
                )
            } catch (e: GeolocationException) {
                LOGGER.warn("Failed gettting list of caches by geolocation for ip " + ip + " delivery service id '" + deliveryServiceId + "'")
            }
        }
        if (caches == null || caches.isEmpty()) {
            return null
        }
        val pathToHash: String = buildPatternBasedHashString(deliveryService, request)
        return consistentHasher.selectHashable(caches, deliveryService.getDispersion(), pathToHash)
    }

    /**
     * Builds a string to be used for consistent hashing based on a client's request *path*.
     * @param deliveryServiceId The "xml_id" of a Delivery Service, the consistent hash settings of
     * which will be used to build the consistent hashing string.
     * @param requestPath The client's requested path.
     * @return A string suitable for using in consistent hashing.
     */
    fun buildPatternBasedHashStringDeliveryService(deliveryServiceId: String?, requestPath: String?): String {
        val r: HTTPRequest = HTTPRequest()
        r.setPath(requestPath)
        r.setQueryString("")
        return buildPatternBasedHashString(cacheRegister!!.getDeliveryService(deliveryServiceId), r)
    }

    /**
     * Returns whether or not the given Delivery Service is of the STEERING or CLIENT_STEERING type.
     */
    private fun isSteeringDeliveryService(deliveryService: DeliveryService?): Boolean {
        return deliveryService != null && steeringRegistry!!.has(deliveryService.getId())
    }

    /**
     * Checks whether the given client's HTTP request is for a CLIENT_STEERING Delivery Service.
     */
    private fun isMultiRouteRequest(request: HTTPRequest): Boolean {
        val deliveryService: DeliveryService? = cacheRegister!!.getDeliveryService(request)
        if (deliveryService == null || !isSteeringDeliveryService(deliveryService)) {
            return false
        }
        return steeringRegistry!!.get(deliveryService.getId())!!.isClientSteering()
    }

    /**
     * Gets a geographic location for the client based on their IP address.
     * @param clientIP The client's IP address as a string.
     * @param deliveryService The Delivery Service the client is requesting. This is used to
     * determine the appropriate location if the client cannot be located, or is blocked by RGB
     * or Anonymous Blocking rules.
     * @return The client's calculated geographic location, or `null` if they cannot be
     * geo-located (and deliveryService has no default "miss" location set) or if the client is
     * blocked by the Delivery Service's settings.
     */
    protected fun getClientLocationByCoverageZoneOrGeo(
        clientIP: String?,
        deliveryService: DeliveryService?
    ): Geolocation? {
        var clientLocation: Geolocation?
        val networkNode: NetworkNode? = getNetworkNode(clientIP)
        if (networkNode != null && networkNode.getGeolocation() != null) {
            clientLocation = networkNode.getGeolocation()
        } else {
            try {
                clientLocation = getLocation(clientIP, deliveryService)
            } catch (e: GeolocationException) {
                clientLocation = null
            }
        }
        return deliveryService!!.supportLocation(clientLocation)
    }

    /**
     * Sorts the provided steering results by their geographic proximity to the client and their
     * configured ordering and weights.
     * @param steeringResults The results to be sorted. They are sorted "in place" - this modifies
     * the list directly.
     * @param clientIP The client's IP address as a string. This is used to calculate their
     * geographic location.
     * @param deliveryService The Delivery Service being served. This is used to help geo-locate the
     * client according to blocking and fallback configuration.
     */
    protected fun geoSortSteeringResults(
        steeringResults: List<SteeringResult>,
        clientIP: String?,
        deliveryService: DeliveryService?
    ) {
        if (((clientIP == null) || clientIP.isEmpty()
                    || steeringResults.stream()
                .allMatch(Predicate({ t: SteeringResult -> t.getSteeringTarget().getGeolocation() == null })))
        ) {
            return
        }
        val clientLocation: Geolocation? = getClientLocationByCoverageZoneOrGeo(clientIP, deliveryService)
        if (clientLocation != null) {
            Collections.sort(steeringResults, SteeringGeolocationComparator(clientLocation))
            Collections.sort(
                steeringResults,
                Comparator.comparingInt(ToIntFunction({ s: SteeringResult -> s.getSteeringTarget().getOrder() }))
            ) // re-sort by order to preserve the ordering done by ConsistentHasher
        }
    }

    fun consistentHashMultiDeliveryService(
        deliveryService: DeliveryService?,
        request: HTTPRequest
    ): MutableList<SteeringResult>? {
        if (deliveryService == null) {
            return null
        }
        val steeringResults: MutableList<SteeringResult> = ArrayList()
        if (!isSteeringDeliveryService(deliveryService)) {
            steeringResults.add(SteeringResult(null, deliveryService))
            return steeringResults
        }
        val steering: Steering? = steeringRegistry!!.get(deliveryService.getId())

        // Pattern based consistent hashing
        val pathToHash: String = buildPatternBasedHashString(deliveryService, request)
        val steeringTargets: List<SteeringTarget?>? =
            consistentHasher.selectHashables(steering.getTargets(), pathToHash)
        for (steeringTarget: SteeringTarget? in steeringTargets!!) {
            val target: DeliveryService? = cacheRegister.getDeliveryService(steeringTarget.getDeliveryService())
            if (target != null) { // target might not be in CRConfig yet
                steeringResults.add(SteeringResult(steeringTarget, target))
            }
        }
        return steeringResults
    }

    /**
     * Chooses a [Cache] for a Steering Delivery Service target based on the Coverage Zone
     * File given a clients IP and request *path*.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param requestPath The client's requested path - e.g.
     * `http://test.example.com/request/path`  `/request/path`
     * @return A cache object chosen to serve the client's request
     */
    fun consistentHashSteeringForCoverageZone(ip: String, deliveryServiceId: String, requestPath: String?): Cache? {
        val r: HTTPRequest = HTTPRequest()
        r.setPath(requestPath)
        r.setQueryString("")
        return consistentHashSteeringForCoverageZone(ip, deliveryServiceId, r)
    }

    /**
     * Chooses a [Cache] for a Steering Delivery Service target based on the Coverage Zone
     * File given a clients IP and request.
     * @param ip The client's IP address
     * @param deliveryServiceId The "xml_id" of a Delivery Service being routed
     * @param request The client's HTTP request
     * @return A cache object chosen to serve the client's request
     */
    fun consistentHashSteeringForCoverageZone(ip: String, deliveryServiceId: String, request: HTTPRequest): Cache? {
        val deliveryService: DeliveryService? = consistentHashDeliveryService(deliveryServiceId, request)
        if (deliveryService == null) {
            LOGGER.error("Failed getting delivery service from cache register for id '" + deliveryServiceId + "'")
            return null
        }
        val requestVersion: IPVersions = if (ip.contains(":")) IPVersions.IPV6ONLY else IPVersions.IPV4ONLY
        val coverageZoneCacheLocation: CacheLocation? =
            getCoverageZoneCacheLocation(ip, deliveryService, false, null, requestVersion)
        val caches: List<Cache?>? = selectCachesByCZ(deliveryService, coverageZoneCacheLocation, requestVersion)
        if (caches == null || caches.isEmpty()) {
            return null
        }
        val pathToHash: String = buildPatternBasedHashString(deliveryService, request)
        return consistentHasher.selectHashable(caches, deliveryService.getDispersion(), pathToHash)
    }

    /**
     * Chooses a target Delivery Service of a given Delivery Service to service a given request path
     *
     * @param deliveryServiceId The "xml_id" of the Delivery Service being requested
     * @param requestPath The requested path - e.g.
     * `http://test.example.com/request/path`  `/request/path`
     * @return The chosen target Delivery Service, or null if one could not be determined.
     */
    fun consistentHashDeliveryService(deliveryServiceId: String?, requestPath: String?): DeliveryService? {
        val r: HTTPRequest = HTTPRequest()
        r.setPath(requestPath)
        r.setQueryString("")
        return consistentHashDeliveryService(deliveryServiceId, r)
    }

    /**
     * Chooses a target Delivery Service of a given Delivery Service to service a given request.
     *
     * @param deliveryServiceId The "xml_id" of the Delivery Service being requested
     * @param request The client's HTTP request
     * @return The chosen target Delivery Service, or null if one could not be determined.
     */
    fun consistentHashDeliveryService(deliveryServiceId: String?, request: HTTPRequest): DeliveryService? {
        return consistentHashDeliveryService(cacheRegister!!.getDeliveryService(deliveryServiceId), request, "")
    }

    /**
     * Chooses a target Delivery Service of a given Delivery Service to service a given request and
     * [.XTC_STEERING_OPTION] value.
     *
     * @param deliveryService The DeliveryService being requested
     * @param request The client's HTTP request
     * @param xtcSteeringOption The value of the client's [.XTC_STEERING_OPTION] HTTP Header.
     * @return The chosen target Delivery Service, or null if one could not be determined.
     */
    fun consistentHashDeliveryService(
        deliveryService: DeliveryService?,
        request: HTTPRequest,
        xtcSteeringOption: String?
    ): DeliveryService? {
        if (deliveryService == null) {
            return null
        }
        if (!isSteeringDeliveryService(deliveryService)) {
            return deliveryService
        }
        val steering: Steering? = steeringRegistry!!.get(deliveryService.getId())
        if (xtcSteeringOption != null && !xtcSteeringOption.isEmpty()) {
            return if (steering!!.hasTarget(xtcSteeringOption)) cacheRegister!!.getDeliveryService(xtcSteeringOption) else null
        }
        val bypassDeliveryServiceId: String? = steering!!.getBypassDestination(request.getPath())
        if (bypassDeliveryServiceId != null && !bypassDeliveryServiceId.isEmpty()) {
            val bypass: DeliveryService? = cacheRegister!!.getDeliveryService(bypassDeliveryServiceId)
            if (bypass != null) { // bypass DS target might not be in CRConfig yet. Until then, try existing targets
                return bypass
            }
        }

        // only select from targets in CRConfig
        val availableTargets: List<SteeringTarget> = steering.getTargets().stream()
            .filter(Predicate({ target: SteeringTarget? -> cacheRegister.getDeliveryService(target.getDeliveryService()) != null }))
            .collect(Collectors.toList())

        // Pattern based consistent hashing
        val pathToHash: String = buildPatternBasedHashString(deliveryService, request)
        val steeringTarget: SteeringTarget? =
            consistentHasher.selectHashable(availableTargets, deliveryService.getDispersion(), pathToHash)

        // set target.consistentHashRegex from steering DS, if it is set
        val targetDeliveryService: DeliveryService? =
            cacheRegister.getDeliveryService(steeringTarget.getDeliveryService())
        if (deliveryService.getConsistentHashRegex() != null && !deliveryService.getConsistentHashRegex().isEmpty()) {
            targetDeliveryService.setConsistentHashRegex(deliveryService.getConsistentHashRegex())
        }
        return targetDeliveryService
    }

    /**
     * Returns a list [Location]s sorted by distance from the client.
     * If the client's location could not be determined, then the list is
     * unsorted.
     *
     * @param locations the collection of Locations to order
     * @return the ordered list of locations
     */
    fun orderLocations(locations: List<Location?>?, clientLocation: Geolocation?): List<Location?>? {
        Collections.sort(locations, LocationComparator(clientLocation))
        return locations
    }

    private fun getClosestCacheLocation(
        cacheLocations: List<CacheLocation?>?,
        clientLocation: Geolocation?,
        deliveryService: DeliveryService?,
        requestVersion: IPVersions?
    ): CacheLocation? {
        if (clientLocation == null) {
            return null
        }
        val orderedLocations: List<CacheLocation?>? =
            orderLocations(cacheLocations, clientLocation) as List<CacheLocation?>?
        for (cacheLocation: CacheLocation? in orderedLocations!!) {
            if (!getSupportingCaches(cacheLocation!!.getCaches(), deliveryService, requestVersion).isEmpty()) {
                return cacheLocation
            }
        }
        return null
    }

    /**
     * Selects a [Cache] from the [CacheLocation] provided.
     *
     * @param location
     * the caches that will considered
     * @param ds
     * the delivery service for the request
     * @return the selected cache or null if none can be found
     */
    private fun selectCaches(
        location: CacheLocation?,
        ds: DeliveryService?,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Trying location: " + location.getId())
        }
        val caches: MutableList<Cache?> = getSupportingCaches(
            location!!.getCaches(), ds, requestVersion
        )
        if (caches.isEmpty()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(
                    ("No online, supporting caches were found at location: "
                            + location.getId())
                )
            }
            return null
        }
        return caches
    }

    /**
     * Gets a DNS zone that contains a given name.
     * @param qname The DNS name that the returned zone will contain. This can include wildcards.
     * @param qtype The
     * [ of the
 * record which will be returned for DNS queries for the returned zone.
 * @param clientAddress The IP address of the client making the DNS request. The zone that is
 * ultimately returned can depend on blocking configuration for a requested Delivery Service,
 * if the qname represents a Delivery Service routing name.
 * @param isDnssecRequest Tells whether or not the request was made using DNSSEC, which will
 * control whether or not the returned zone is signed.
 * @param builder Used to build a zone if one has not already been created containing qname.
 * @return A zone containing records of type qtype that contains qname. This can be null
](https://javadoc.io/doc/dnsjava/dnsjava/latest/org/xbill/DNS/Type.html) */
    fun getZone(
        qname: Name,
        qtype: Int,
        clientAddress: InetAddress,
        isDnssecRequest: Boolean,
        builder: DNSAccessRecord.Builder
    ): Zone? {
        return zoneManager.getZone(qname, qtype, clientAddress, isDnssecRequest, builder)
    }

    private fun enforceGeoRedirect(
        track: StatTracker.Track,
        ds: DeliveryService?,
        clientIp: String?,
        queriedClientLocation: Geolocation?,
        requestVersion: IPVersions
    ): MutableList<Cache?>? {
        val urlType: String? = ds.getGeoRedirectUrlType()
        track.setResult(ResultType.GEO_REDIRECT)
        if (("NOT_DS_URL" == urlType)) {
            // redirect url not belongs to this DS, just redirect it
            return null
        }
        if (!("DS_URL" == urlType)) {
            LOGGER.error("invalid geo redirect url type '" + urlType + "'")
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.GEO_NO_CACHE_FOUND)
            return null
        }
        var clientLocation: Geolocation? = queriedClientLocation

        //redirect url belongs to this DS, will try return the caches
        if (clientLocation == null) {
            try {
                clientLocation = getLocation(clientIp, ds)
            } catch (e: GeolocationException) {
                LOGGER.warn("Failed getting geolocation for client ip " + clientIp + " and delivery service '" + ds.getId() + "'")
            }
        }
        if (clientLocation == null) {
            clientLocation = ds.getMissLocation()
        }
        if (clientLocation == null) {
            LOGGER.error("cannot find a geo location for the client: " + clientIp)
            // particular error was logged in ds.supportLocation
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_CLIENT_GEO_UNSUPPORTED)
            return null
        }
        var caches: MutableList<Cache?>? = null
        try {
            caches = getCachesByGeo(ds, clientLocation, track, requestVersion)
        } catch (e: GeolocationException) {
            LOGGER.error("Failed getting caches by geolocation " + e.message)
        }
        if (caches == null) {
            LOGGER.warn(String.format("No Cache found by Geo in NGB redirect"))
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.GEO_NO_CACHE_FOUND)
        }
        return caches
    }

    @Throws(BeansException::class)
    fun setApplicationContext(applicationContext: ApplicationContext?) {
        this.applicationContext = applicationContext
    }

    fun configurationChanged() {
        if (applicationContext == null) {
            LOGGER.warn("Application Context not yet ready, skipping calling listeners of configuration change")
            return
        }
        val configurationListenerMap: Map<String, ConfigurationListener> = applicationContext!!.getBeansOfType(
            ConfigurationListener::class.java
        )
        for (configurationListener: ConfigurationListener in configurationListenerMap.values) {
            configurationListener.configurationChanged()
        }
    }

    fun setSteeringRegistry(steeringRegistry: SteeringRegistry?) {
        this.steeringRegistry = steeringRegistry
    }

    private fun getEdgeHTTPRoutingLimit(ds: DeliveryService?): Int {
        if ((ds != null) && (ds.getMaxDnsIps() != 0) && (ds.getMaxDnsIps() != edgeHTTPRoutingLimit)) {
            return ds.getMaxDnsIps()
        }
        return edgeHTTPRoutingLimit
    }

    val defaultGeoLocationsOverride: Map<String, Geolocation>
        get() {
            return defaultGeolocationsOverride
        }

    companion object {
        val LOGGER: Logger = Logger.getLogger(TrafficRouter::class.java)

        /**
         * This is an HTTP Header the value of which, if present in a client HTTP request, should be
         * the XMLID of a Delivery Service to use as an explicit target in CLIENT_STEERING (thus
         * bypassing normal steering logic).
         */
        val XTC_STEERING_OPTION: String = "x-tc-steering-option"

        /**
         * This is the key of a JSON object that is a configuration option that may be present in
         * "CRConfig" Snapshots. When this option is present, and is 'true', more Edge-Tier cache
         * servers will be provided in responses to steering requests (known as "Client Steering Forced
         * Diversity").
         */
        val CLIENT_STEERING_DIVERSITY: String = "client.steering.forced.diversity"
        val DNSSEC_ENABLED: String = "dnssec.enabled"
        val DNSSEC_ZONE_DIFFING: String = "dnssec.zone.diffing.enabled"
        private val DEFAULT_EDGE_NS_TTL: Long = 3600
        private val DEFAULT_EDGE_TR_LIMIT: Int = 4
        private val GEO_ZERO_ZERO: Geolocation = Geolocation(0, 0)
        protected val UNABLE_TO_ROUTE_REQUEST: String = "Unable to route request."
        protected val URL_ERR_STR: String = "Unable to create URL."
    }

    /**
     * When instantiated, Traffic Router will try to read all of its various configuration files.
     *
     * @throws IOException when an error occurs reading in a configuration file.
     */
    init {
        cacheRegister = cr
        this.geolocationService = geolocationService
        this.geolocationService6 = geolocationService6
        anonymousIpDatabaseService = anonymousIpService
        this.federationRegistry = federationRegistry
        isClientSteeringDiversityEnabled = optBoolean(cr.getConfig(), CLIENT_STEERING_DIVERSITY)
        isDnssecZoneDiffingEnabled =
            optBoolean(cr.getConfig(), DNSSEC_ENABLED) && optBoolean(cr.getConfig(), DNSSEC_ZONE_DIFFING)
        isConsistentDNSRouting = optBoolean(cr.getConfig(), "consistent.dns.routing") // previous/default behavior
        isEdgeDNSRouting = optBoolean(cr.getConfig(), "edge.dns.routing") && cr.hasEdgeTrafficRouters()
        isEdgeHTTPRouting = optBoolean(cr.getConfig(), "edge.http.routing") && cr.hasEdgeTrafficRouters()
        if (cr.getConfig() != null) {
            // maxmindDefaultOverride: {countryCode: , lat: , long: }
            val geolocations: JsonNode? = cr.getConfig().get("maxmindDefaultOverride")
            if (geolocations != null) {
                for (geolocation: JsonNode? in geolocations) {
                    val countryCode: String = optString(geolocation, "countryCode")
                    val lat: Double = optDouble(geolocation, "lat")
                    val longitude: Double = optDouble(geolocation, "long")
                    defaultGeolocationsOverride.put(countryCode, Geolocation(lat, longitude))
                }
            }
        }
        val ttls: JsonNode? = cacheRegister.getConfig().get("ttls")
        if (ttls != null && ttls.has("NS")) {
            edgeNSttl = optLong(ttls, "NS")
        } else {
            edgeNSttl = DEFAULT_EDGE_NS_TTL
        }
        edgeDNSRoutingLimit = JsonUtils.optInt(cr.getConfig(), "edge.dns.limit", DEFAULT_EDGE_TR_LIMIT)
        edgeHTTPRoutingLimit = JsonUtils.optInt(
            cr.getConfig(),
            "edge.http.limit",
            DEFAULT_EDGE_TR_LIMIT
        ) // NOTE: this can be overridden per-DS via maxDnsAnswers
        zoneManager = ZoneManager(this, statTracker, trafficOpsUtils, trafficRouterManager)
    }
}