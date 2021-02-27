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
package com.comcast.cdn.traffic_control.traffic_router.core.config

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
import com.comcast.cdn.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesResponse
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import com.comcast.cdn.traffic_control.traffic_router.core.request.RequestMatcher
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import org.springframework.context.event.ContextClosedEvent
import java.lang.IllegalArgumentException
import java.net.*
import java.util.*
import java.util.function.Consumer
import java.util.function.Function
import java.util.function.Predicate
import java.util.stream.Stream

class ConfigHandler constructor() {
    private var trafficRouterManager: TrafficRouterManager? = null
    var geolocationDatabaseUpdater: GeolocationDatabaseUpdater? = null
    var statTracker: StatTracker? = null
    var configDir: String? = null
    var trafficRouterId: String? = null
    private var trafficOpsUtils: TrafficOpsUtils? = null
    var networkUpdater: NetworkUpdater? = null
    var deepNetworkUpdater: DeepNetworkUpdater? = null
    private var federationsWatcher: FederationsWatcher? = null
    var regionalGeoUpdater: RegionalGeoUpdater? = null
    var anonymousIpConfigUpdater: AnonymousIpConfigUpdater? = null
    var anonymousIpDatabaseUpdater: AnonymousIpDatabaseUpdater? = null
    private var steeringWatcher: SteeringWatcher? = null
    private var letsEncryptDnsChallengeWatcher: LetsEncryptDnsChallengeWatcher? = null
    private var certificatesPoller: CertificatesPoller? = null
    var certificatesPublisher: CertificatesPublisher? = null
    var publishStatusQueue: BlockingQueue<Boolean>? = null
    private val cancelled: AtomicBoolean = AtomicBoolean(false)
    private val isProcessing: AtomicBoolean = AtomicBoolean(false)
    @Throws(JsonUtilsException::class, IOException::class)
    fun processConfig(jsonStr: String?): Boolean {
        isProcessing.set(true)
        LOGGER.info("Entered processConfig")
        if (jsonStr == null) {
            trafficRouterManager!!.setCacheRegister(null)
            cancelled.set(false)
            isProcessing.set(false)
            publishStatusQueue!!.clear()
            LOGGER.info("Exiting processConfig: No json data to process")
            return false
        }
        var date: Date
        synchronized(configSync, {
            val mapper: ObjectMapper = ObjectMapper()
            val jo: JsonNode = mapper.readTree(jsonStr)
            val config: JsonNode? = JsonUtils.getJsonNode(jo, "config")
            val stats: JsonNode? = JsonUtils.getJsonNode(jo, "stats")
            val sts: Long = getSnapshotTimestamp(stats)
            date = Date(sts * 1000L)
            if (sts <= lastSnapshotTimestamp) {
                cancelled.set(false)
                isProcessing.set(false)
                publishStatusQueue!!.clear()
                LOGGER.info("Exiting processConfig: Incoming TrConfig snapshot timestamp (" + sts + ") is older or equal to the loaded timestamp (" + lastSnapshotTimestamp + "); unable to process")
                return false
            }
            try {
                parseGeolocationConfig(config)
                parseCoverageZoneNetworkConfig(config)
                parseDeepCoverageZoneNetworkConfig(config)
                parseRegionalGeoConfig(jo)
                parseAnonymousIpConfig(jo)
                val cacheRegister: CacheRegister = CacheRegister()
                val deliveryServicesJson: JsonNode? = JsonUtils.getJsonNode(jo, deliveryServicesKey)
                cacheRegister.setTrafficRouters(JsonUtils.getJsonNode(jo, "contentRouters"))
                cacheRegister.setConfig(config)
                cacheRegister.setStats(stats)
                parseTrafficOpsConfig(config, stats)
                val deliveryServiceMap: Map<String?, DeliveryService>? =
                    parseDeliveryServiceConfig(JsonUtils.getJsonNode(jo, deliveryServicesKey))
                parseCertificatesConfig(config)
                certificatesPublisher.setDeliveryServicesJson(deliveryServicesJson)
                val deliveryServices: ArrayList<DeliveryService> = ArrayList()
                if (deliveryServiceMap != null && !deliveryServiceMap.values.isEmpty()) {
                    deliveryServices.addAll(deliveryServiceMap.values)
                }
                if (deliveryServiceMap != null && !deliveryServiceMap.values.isEmpty()) {
                    certificatesPublisher.setDeliveryServices(deliveryServices)
                }
                certificatesPoller!!.restart()
                val httpsDeliveryServices: List<DeliveryService> = deliveryServices.stream().filter(
                    Predicate({ ds: DeliveryService -> !ds.isDns() && ds.isSslEnabled() })
                ).collect(Collectors.toList())
                httpsDeliveryServices.forEach(Consumer({ ds: DeliveryService -> LOGGER.info("Checking for certificate for " + ds.getId()) }))
                if (!httpsDeliveryServices.isEmpty()) {
                    try {
                        publishStatusQueue!!.put(true)
                    } catch (e: InterruptedException) {
                        LOGGER.warn("Failed to notify certificates publisher we're waiting for certificates", e)
                    }
                    while (!cancelled.get() && !publishStatusQueue!!.isEmpty()) {
                        try {
                            LOGGER.info(
                                "Waiting for https certificates to support new config " + String.format(
                                    "%x",
                                    publishStatusQueue.hashCode()
                                )
                            )
                            Thread.sleep(1000L)
                        } catch (t: Throwable) {
                            LOGGER.warn("Interrupted while waiting for status on publishing ssl certs", t)
                        }
                    }
                }
                if (cancelled.get()) {
                    cancelled.set(false)
                    isProcessing.set(false)
                    publishStatusQueue!!.clear()
                    LOGGER.info("Exiting processConfig: processing of config with timestamp " + date + " was cancelled")
                    return false
                }
                parseDeliveryServiceMatchSets(deliveryServicesJson, deliveryServiceMap, cacheRegister)
                parseLocationConfig(JsonUtils.getJsonNode(jo, "edgeLocations"), cacheRegister)
                parseEdgeTrafficRouterLocations(jo, cacheRegister)
                parseCacheConfig(JsonUtils.getJsonNode(jo, "contentServers"), cacheRegister)
                if (jo.has(topologiesKey)) {
                    parseTopologyConfig(JsonUtils.getJsonNode(jo, topologiesKey), deliveryServiceMap, cacheRegister)
                }
                parseMonitorConfig(JsonUtils.getJsonNode(jo, "monitors"))
                federationsWatcher!!.configure(config)
                steeringWatcher!!.configure(config)
                letsEncryptDnsChallengeWatcher!!.configure(config)
                trafficRouterManager!!.setCacheRegister(cacheRegister)
                trafficRouterManager.getNameServer().setEcsEnable(JsonUtils.optBoolean(config, "ecsEnable", false))
                trafficRouterManager.getNameServer().setEcsEnabledDses(
                    deliveryServices.stream().filter(Predicate({ obj: DeliveryService -> obj.isEcsEnabled() }))
                        .collect(Collectors.toSet())
                )
                trafficRouterManager.getTrafficRouter()
                    .setRequestHeaders(parseRequestHeaders(config!!.get("requestHeaders")))
                trafficRouterManager.getTrafficRouter().configurationChanged()


                /*
				 * NetworkNode uses lazy loading to associate CacheLocations with NetworkNodes at request time in TrafficRouter.
				 * Therefore this must be done last, as any thread that holds a reference to the CacheRegister might contain a reference
				 * to a Cache that no longer exists. In that case, the old CacheLocation and List<Cache> will be set on a
				 * given CacheLocation within a NetworkNode, leading to an OFFLINE cache to be served, or an ONLINE cache to
				 * never have traffic routed to it, as the old List<Cache> does not contain the Cache that was moved to ONLINE.
				 * NetworkNode is a singleton and is managed asynchronously. As long as we swap out the CacheRegister first,
				 * then clear cache locations, the lazy loading should work as designed. See issue TC-401 for details.
				 *
				 * Update for DDC (Dynamic Deep Caching): NetworkNode now has a 2nd singleton (deepInstance) that is managed
				 * similarly to the non-deep instance. However, instead of clearing a NetworkNode's CacheLocation, only the
				 * Caches are cleared from the CacheLocation then lazily loaded at request time.
				 */NetworkNode.Companion.getInstance()!!.clearLocations()
                NetworkNode.Companion.getDeepInstance()!!.clearLocations(true)
                lastSnapshotTimestamp = sts
            } catch (e: ParseException) {
                isProcessing.set(false)
                cancelled.set(false)
                publishStatusQueue!!.clear()
                LOGGER.error("Exiting processConfig: Failed to process config for snapshot from " + date, e)
                return false
            }
        })
        LOGGER.info("Exit: processConfig, successfully applied snapshot from " + date)
        isProcessing.set(false)
        cancelled.set(false)
        publishStatusQueue!!.clear()
        return true
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    /**
     * Parses the Traffic Ops config
     * @param config
     * the [TrafficRouterConfiguration] config section
     * @param stats
     * the [TrafficRouterConfiguration] stats section
     *
     * @throws JsonUtilsException
     */
    @Throws(JsonUtilsException::class)
    private fun parseTrafficOpsConfig(config: JsonNode?, stats: JsonNode?) {
        if (stats!!.has("tm_host")) {
            trafficOpsUtils.setHostname(JsonUtils.getString(stats, "tm_host"))
        } else if (stats.has("to_host")) {
            trafficOpsUtils.setHostname(JsonUtils.getString(stats, "to_host"))
        } else {
            throw JsonUtilsException("Unable to find to_host or tm_host in stats section of TrConfig; unable to build TrafficOps URLs")
        }
        trafficOpsUtils.setCdnName(JsonUtils.optString(stats, "CDN_name", null))
        trafficOpsUtils!!.setConfig(config)
    }

    /**
     * Parses the cache information from the configuration and updates the [CacheRegister].
     *
     * @param trConfig
     * the [TrafficRouterConfiguration]
     * @throws JsonUtilsException, ParseException
     */
    @Throws(JsonUtilsException::class, ParseException::class)
    private fun parseCacheConfig(contentServers: JsonNode?, cacheRegister: CacheRegister) {
        val map: MutableMap<String?, Cache?> = HashMap()
        val statMap: MutableMap<String?, MutableList<String>> = HashMap()
        val nodeIter: Iterator<String> = contentServers!!.fieldNames()
        while (nodeIter.hasNext()) {
            val node: String = nodeIter.next()
            val jo: JsonNode? = JsonUtils.getJsonNode(contentServers, node)
            val loc: CacheLocation? = cacheRegister.getCacheLocation(JsonUtils.getString(jo, "locationId"))
            if (loc != null) {
                var hashId: String = node
                // not only must we check for the key, but also if it's null; problems with consistent hashing can arise if we use a null value as the hashId
                if (jo!!.has("hashId") && jo.get("hashId").textValue() != null) {
                    hashId = jo.get("hashId").textValue()
                }
                val cache: Cache = Cache(node, hashId, optInt(jo, "hashCount"), loc.getGeolocation())
                cache.setFqdn(JsonUtils.getString(jo, "fqdn"))
                cache.setPort(JsonUtils.getInt(jo, "port"))
                if (jo.has("capabilities")) {
                    val capabilities: MutableSet<String?> = HashSet()
                    val capabilitiesNode: JsonNode = jo.get("capabilities")
                    if (!capabilitiesNode.isArray()) {
                        LOGGER.error("Server '" + hashId + "' has malformed capabilities. Disregarding.")
                    } else {
                        capabilitiesNode.forEach(Consumer({ capabilityNode: JsonNode ->
                            val capability: String = capabilityNode.asText()
                            if (!capability.isEmpty()) {
                                capabilities.add(capability)
                            }
                        }))
                    }
                    cache.addCapabilities(capabilities)
                }
                val ip: String? = JsonUtils.getString(jo, "ip")
                val ip6: String = optString(jo, "ip6")
                try {
                    cache.setIpAddress(ip, ip6, 0)
                } catch (e: UnknownHostException) {
                    LOGGER.warn(e.toString() + " : " + ip)
                }
                if (jo.has(deliveryServicesKey)) {
                    val references: MutableList<DeliveryServiceReference> = ArrayList()
                    val dsJos: JsonNode = jo.get(deliveryServicesKey)
                    val dsIter: Iterator<String> = dsJos.fieldNames()
                    while (dsIter.hasNext()) {
                        /* technically this could be more than just a string or array,
						 * but, as we only have had those two types, let's not worry about the future
						 */
                        val ds: String = dsIter.next()
                        val dso: JsonNode? = dsJos.get(ds)
                        var dsNames: MutableList<String>? = statMap.get(ds)
                        if (dsNames == null) {
                            dsNames = ArrayList()
                        }
                        if (dso!!.isArray()) {
                            if (dso != null && dso.size() > 0) {
                                var i: Int = 0
                                for (nameNode: JsonNode in dso) {
                                    val name: String = nameNode.asText()
                                    if (i == 0) {
                                        references.add(DeliveryServiceReference(ds, name))
                                    }
                                    val tld: String = optString(cacheRegister.getConfig(), "domain_name")
                                    val dsName: String = getDsName(name, tld)
                                    if (!dsNames.contains(dsName)) {
                                        dsNames.add(dsName)
                                    }
                                    i++
                                }
                            }
                        } else {
                            references.add(DeliveryServiceReference(ds, dso.toString()))
                            if (!dsNames.contains(dso.toString())) {
                                dsNames.add(dso.toString())
                            }
                        }
                        statMap.put(ds, dsNames)
                    }
                    cache.setDeliveryServices(references)
                }
                loc.addCache(cache)
                map.put(cache.getId(), cache)
            }
        }
        cacheRegister.setCacheMap(map)
        statTracker!!.initialize(statMap, cacheRegister)
    }

    @Throws(JsonUtilsException::class)
    private fun parseDeliveryServiceConfig(allDeliveryServices: JsonNode?): Map<String?, DeliveryService> {
        val deliveryServiceMap: MutableMap<String?, DeliveryService> = HashMap()
        val deliveryServiceIter: Iterator<String> = allDeliveryServices!!.fieldNames()
        while (deliveryServiceIter.hasNext()) {
            val deliveryServiceId: String = deliveryServiceIter.next()
            val deliveryServiceJson: JsonNode? = JsonUtils.getJsonNode(allDeliveryServices, deliveryServiceId)
            val deliveryService: DeliveryService = DeliveryService(deliveryServiceId, deliveryServiceJson)
            var isDns: Boolean = false
            val matchsets: JsonNode? = JsonUtils.getJsonNode(deliveryServiceJson, "matchsets")
            for (matchset: JsonNode in matchsets!!) {
                val protocol: String? = JsonUtils.getString(matchset, "protocol")
                if (("DNS" == protocol)) {
                    isDns = true
                }
            }
            deliveryService.setDns(isDns)
            deliveryServiceMap.put(deliveryServiceId, deliveryService)
        }
        return deliveryServiceMap
    }

    private fun getDsName(name: String, tld: String): String {
        return if (name.endsWith(tld)) name.replace("^.*?\\.".toRegex(), "") else name
    }

    private fun parseTopologyConfig(
        allTopologies: JsonNode?,
        deliveryServiceMap: Map<String?, DeliveryService>?,
        cacheRegister: CacheRegister
    ) {
        val topologyMap: MutableMap<String?, List<String>> = HashMap()
        val statMap: MutableMap<String?, MutableList<String>> = HashMap()
        val tld: String = optString(cacheRegister.getConfig(), "domain_name")
        allTopologies!!.fieldNames().forEachRemaining(Consumer({ topologyName: String? ->
            val nodes: MutableList<String> = ArrayList()
            allTopologies.get(topologyName).get("nodes")
                .forEach(Consumer({ cache: JsonNode -> nodes.add(cache.textValue()) }))
            topologyMap.put(topologyName, nodes)
        }))
        deliveryServiceMap!!.forEach(BiConsumer({ xmlId: String?, ds: DeliveryService ->
            val dsReferences: MutableList<DeliveryServiceReference> = ArrayList()
            val dsNames: MutableList<String> = ArrayList() // for stats
            Stream.of(ds.getTopology())
                .filter(Predicate({ topologyName: String? ->
                    !Objects.isNull(topologyName) && topologyMap.containsKey(
                        topologyName
                    )
                }))
                .flatMap(Function<String?, Stream<out String>>({ topologyName: String? ->
                    statMap.put(ds.getId(), dsNames)
                    topologyMap.get(topologyName)!!.stream()
                }))
                .flatMap(Function<String, Stream<out Cache?>>({ node: String? ->
                    cacheRegister.getCacheLocation(node)!!
                        .getCaches().stream()
                }))
                .filter(Predicate({ cache: Cache -> ds.hasRequiredCapabilities(cache.getCapabilities()) }))
                .forEach(Consumer({ cache: Cache ->
                    cacheRegister.getDeliveryServiceMatchers(ds).stream()
                        .flatMap(Function<DeliveryServiceMatcher?, Stream<out RequestMatcher?>>({ deliveryServiceMatcher: DeliveryServiceMatcher? ->
                            deliveryServiceMatcher!!.getRequestMatchers().stream()
                        }))
                        .map<String>(Function({ requestMatcher: RequestMatcher ->
                            requestMatcher.getPattern().pattern()
                        }))
                        .forEach(Consumer({ pattern: String ->
                            val remap: String? = ds.getRemap(pattern)
                            val fqdn: String =
                                if (pattern.contains(".*") && !ds.isDns()) cache.getId() + "." + remap else (remap)!!
                            dsNames.add(getDsName(fqdn, tld))
                            if (!(remap == if (ds.isDns()) ds.getRoutingName() + "." + ds.getDomain() else ds.getDomain())) {
                                return@forEach
                            }
                            try {
                                dsReferences.add(DeliveryServiceReference(ds.getId(), fqdn))
                            } catch (e: ParseException) {
                                LOGGER.error(
                                    "Unable to create a DeliveryServiceReference from DeliveryService '" + ds.getId() + "'",
                                    e
                                )
                            }
                        }))
                    cache.setDeliveryServices(dsReferences)
                }))
        }))
        statTracker!!.initialize(statMap, cacheRegister)
    }

    @Throws(JsonUtilsException::class)
    private fun parseDeliveryServiceMatchSets(
        allDeliveryServices: JsonNode?,
        deliveryServiceMap: Map<String?, DeliveryService>?,
        cacheRegister: CacheRegister
    ) {
        val deliveryServiceMatchers: TreeSet<DeliveryServiceMatcher> = TreeSet()
        val config: JsonNode? = cacheRegister.getConfig()
        val regexSuperhackEnabled: Boolean = JsonUtils.optBoolean(config, "confighandler.regex.superhack.enabled", true)
        val deliveryServiceIds: Iterator<String> = allDeliveryServices!!.fieldNames()
        while (deliveryServiceIds.hasNext()) {
            val deliveryServiceId: String = deliveryServiceIds.next()
            val deliveryServiceJson: JsonNode? = JsonUtils.getJsonNode(allDeliveryServices, deliveryServiceId)
            val matchsets: JsonNode? = JsonUtils.getJsonNode(deliveryServiceJson, "matchsets")
            val deliveryService: DeliveryService? = deliveryServiceMap!!.get(deliveryServiceId)
            for (i in 0 until matchsets!!.size()) {
                val matchset: JsonNode = matchsets.get(i)
                val deliveryServiceMatcher: DeliveryServiceMatcher = DeliveryServiceMatcher(deliveryService)
                deliveryServiceMatchers.add(deliveryServiceMatcher)
                val list: JsonNode? = JsonUtils.getJsonNode(matchset, "matchlist")
                for (j in 0 until list!!.size()) {
                    val matcherJo: JsonNode = list.get(j)
                    val type: DeliveryServiceMatcher.Type =
                        DeliveryServiceMatcher.Type.valueOf(JsonUtils.getString(matcherJo, "match-type"))
                    val target: String = optString(matcherJo, "target")
                    var regex: String? = JsonUtils.getString(matcherJo, "regex")
                    if (regexSuperhackEnabled && (i == 0) && (j == 0) && (type == DeliveryServiceMatcher.Type.HOST)) {
                        regex = regex!!.replaceFirst("^\\.\\*\\\\\\.".toRegex(), "(.*\\\\.|^)")
                    }
                    deliveryServiceMatcher.addMatch(type, regex, target)
                }
            }
        }
        cacheRegister.setDeliveryServiceMap(deliveryServiceMap)
        cacheRegister.setDeliveryServiceMatchers(deliveryServiceMatchers)
        initGeoFailedRedirect(deliveryServiceMap, cacheRegister)
    }

    private fun initGeoFailedRedirect(dsMap: Map<String?, DeliveryService>?, cacheRegister: CacheRegister) {
        val itr: Iterator<String?> = dsMap!!.keys.iterator()
        while (itr.hasNext()) {
            val ds: DeliveryService? = dsMap.get(itr.next())
            //check if it's relative path or not
            val rurl: String? = ds.getGeoRedirectUrl()
            if (rurl == null) {
                continue
            }
            try {
                val idx: Int = rurl.indexOf("://")
                if (idx < 0) {
                    //this is a relative url, belongs to this ds
                    ds.setGeoRedirectUrlType("DS_URL")
                    continue
                }
                //this is a url with protocol, must check further
                //first, parse the url, if url invalid it will throw Exception
                val url: URL = URL(rurl)

                //make a fake HTTPRequest for the redirect url
                val req: HTTPRequest = HTTPRequest(url)
                ds.setGeoRedirectFile(url.getFile())
                //try select the ds by the redirect fake HTTPRequest
                val rds: DeliveryService? = cacheRegister.getDeliveryService(req)
                if (rds == null || rds.getId() !== ds.getId()) {
                    //the redirect url not belongs to this ds
                    ds.setGeoRedirectUrlType("NOT_DS_URL")
                    continue
                }
                ds.setGeoRedirectUrlType("DS_URL")
            } catch (e: Exception) {
                LOGGER.error("fatal error, failed to init NGB redirect with Exception: " + e.message)
            }
        }
    }

    /**
     * Parses the geolocation database configuration and updates the database if the URL has
     * changed.
     *
     * @param config
     * the [TrafficRouterConfiguration]
     * @throws JsonUtilsException
     */
    @Throws(JsonUtilsException::class)
    private fun parseGeolocationConfig(config: JsonNode?) {
        var pollingUrlKey: String = "geolocation.polling.url"
        if (config!!.has("alt.geolocation.polling.url")) {
            pollingUrlKey = "alt.geolocation.polling.url"
        }
        geolocationDatabaseUpdater!!.setDataBaseURL(
            JsonUtils.getString(config, pollingUrlKey),
            optLong(config, "geolocation.polling.interval")
        )
        if (config.has(NEUSTAR_POLLING_URL)) {
            System.setProperty(NEUSTAR_POLLING_URL, JsonUtils.getString(config, NEUSTAR_POLLING_URL))
        }
        if (config.has(NEUSTAR_POLLING_INTERVAL)) {
            System.setProperty(NEUSTAR_POLLING_INTERVAL, JsonUtils.getString(config, NEUSTAR_POLLING_INTERVAL))
        }
    }

    private fun parseCertificatesConfig(config: JsonNode?) {
        val pollingInterval: String = "certificates.polling.interval"
        if (config!!.has(pollingInterval)) {
            try {
                System.setProperty(pollingInterval, JsonUtils.getString(config, pollingInterval))
            } catch (e: Exception) {
                LOGGER.warn("Failed to set system property " + pollingInterval + " from configuration object: " + e.message)
            }
        }
    }

    @Throws(JsonUtilsException::class)
    private fun parseAnonymousIpConfig(jo: JsonNode) {
        val anonymousPollingUrl: String = "anonymousip.polling.url"
        val anonymousPollingInterval: String = "anonymousip.polling.interval"
        val anonymousPolicyConfiguration: String = "anonymousip.policy.configuration"
        val config: JsonNode? = JsonUtils.getJsonNode(jo, "config")
        val configUrl: String? = JsonUtils.optString(config, anonymousPolicyConfiguration, null)
        val databaseUrl: String? = JsonUtils.optString(config, anonymousPollingUrl, null)
        if (configUrl == null) {
            LOGGER.info(anonymousPolicyConfiguration + " not configured; stopping service updater and disabling feature")
            anonymousIpConfigUpdater!!.stopServiceUpdater()
            AnonymousIp.Companion.getCurrentConfig().enabled = false
            return
        }
        if (databaseUrl == null) {
            LOGGER.info(anonymousPollingUrl + " not configured; stopping service updater and disabling feature")
            anonymousIpDatabaseUpdater!!.stopServiceUpdater()
            AnonymousIp.Companion.getCurrentConfig().enabled = false
            return
        }
        if (jo.has(deliveryServicesKey)) {
            val dss: JsonNode? = JsonUtils.getJsonNode(jo, deliveryServicesKey)
            val dsNames: Iterator<String> = dss!!.fieldNames()
            while (dsNames.hasNext()) {
                val ds: String = dsNames.next()
                val dsNode: JsonNode? = JsonUtils.getJsonNode(dss, ds)
                if ((optString(dsNode, "anonymousBlockingEnabled") == "true")) {
                    val interval: Long = optLong(config, anonymousPollingInterval)
                    anonymousIpConfigUpdater!!.setDataBaseURL(configUrl, interval)
                    anonymousIpDatabaseUpdater!!.setDataBaseURL(databaseUrl, interval)
                    AnonymousIp.Companion.getCurrentConfig().enabled = true
                    LOGGER.debug("Anonymous Blocking in use, scheduling service updaters and enabling feature")
                    return
                }
            }
        }
        LOGGER.debug("No DS using anonymous ip blocking - disabling feature")
        anonymousIpConfigUpdater!!.cancelServiceUpdater()
        anonymousIpDatabaseUpdater!!.cancelServiceUpdater()
        AnonymousIp.Companion.getCurrentConfig().enabled = false
    }

    /**
     * Parses the ConverageZoneNetwork database configuration and updates the database if the URL has
     * changed.
     *
     * @param trConfig
     * the [TrafficRouterConfiguration]
     * @throws JsonUtilsException
     */
    @Throws(JsonUtilsException::class)
    private fun parseCoverageZoneNetworkConfig(config: JsonNode?) {
        networkUpdater!!.setDataBaseURL(
            JsonUtils.getString(config, "coveragezone.polling.url"),
            optLong(config, "coveragezone.polling.interval")
        )
    }

    @Throws(JsonUtilsException::class)
    private fun parseDeepCoverageZoneNetworkConfig(config: JsonNode?) {
        deepNetworkUpdater!!.setDataBaseURL(
            JsonUtils.optString(config, "deepcoveragezone.polling.url", null),
            optLong(config, "deepcoveragezone.polling.interval")
        )
    }

    @Throws(JsonUtilsException::class)
    private fun parseRegionalGeoConfig(jo: JsonNode) {
        val config: JsonNode? = JsonUtils.getJsonNode(jo, "config")
        val url: String? = JsonUtils.optString(config, "regional_geoblock.polling.url", null)
        if (url == null) {
            LOGGER.info("regional_geoblock.polling.url not configured; stopping service updater")
            regionalGeoUpdater!!.stopServiceUpdater()
            return
        }
        if (jo.has(deliveryServicesKey)) {
            val dss: JsonNode = jo.get(deliveryServicesKey)
            for (ds: JsonNode in dss) {
                if (ds.has("regionalGeoBlocking") && (JsonUtils.getString(ds, "regionalGeoBlocking") == "true")) {
                    val interval: Long = optLong(config, "regional_geoblock.polling.interval")
                    regionalGeoUpdater!!.setDataBaseURL(url, interval)
                    return
                }
            }
        }
        regionalGeoUpdater!!.cancelServiceUpdater()
    }

    /**
     * Creates a [Map] of location IDs to [Geolocation]s for every [Location]
     * included in the configuration that has both a latitude and a longitude specified.
     *
     * @param trConfig
     * the TrafficRouterConfiguration
     * @return the [Map], empty if there are no Locations that have both a latitude and
     * longitude specified
     * @throws JsonUtilsException
     */
    @Throws(JsonUtilsException::class)
    private fun parseLocationConfig(locationsJo: JsonNode?, cacheRegister: CacheRegister) {
        val locations: MutableSet<CacheLocation> = HashSet(locationsJo!!.size())
        val locIter: Iterator<String> = locationsJo.fieldNames()
        while (locIter.hasNext()) {
            val loc: String = locIter.next()
            val jo: JsonNode? = JsonUtils.getJsonNode(locationsJo, loc)
            var backupCacheGroups: MutableList<String>? = null
            var useClosestOnBackupFailure: Boolean = true
            if (jo != null && jo.has("backupLocations")) {
                val backupConfigJson: JsonNode? = JsonUtils.getJsonNode(jo, "backupLocations")
                backupCacheGroups = ArrayList()
                if (backupConfigJson!!.has("list")) {
                    for (cacheGroup: JsonNode in JsonUtils.getJsonNode(backupConfigJson, "list")) {
                        backupCacheGroups.add(cacheGroup.asText())
                    }
                    useClosestOnBackupFailure = JsonUtils.optBoolean(backupConfigJson, "fallbackToClosest", false)
                }
            }
            val enabledLocalizationMethods: MutableSet<LocalizationMethod?> = parseLocalizationMethods(loc, jo)
            try {
                locations.add(
                    CacheLocation(
                        loc,
                        Geolocation(
                            JsonUtils.getDouble(jo, "latitude"),
                            JsonUtils.getDouble(jo, "longitude")
                        ),
                        backupCacheGroups,
                        useClosestOnBackupFailure,
                        enabledLocalizationMethods
                    )
                )
            } catch (e: JsonUtilsException) {
                LOGGER.warn(e, e)
            }
        }
        cacheRegister.setConfiguredLocations(locations)
    }

    @Throws(JsonUtilsException::class)
    private fun parseLocalizationMethods(loc: String, jo: JsonNode?): MutableSet<LocalizationMethod?> {
        val enabledLocalizationMethods: MutableSet<LocalizationMethod?> = HashSet()
        if ((jo != null) && jo.hasNonNull(LOCALIZATION_METHODS) && JsonUtils.getJsonNode(jo, LOCALIZATION_METHODS)
                .isArray()
        ) {
            val localizationMethodsJson: JsonNode? = JsonUtils.getJsonNode(jo, LOCALIZATION_METHODS)
            for (methodJson: JsonNode in localizationMethodsJson!!) {
                if (methodJson.isNull() || !methodJson.isTextual()) {
                    LOGGER.error("Location '" + loc + "' has a non-string localizationMethod, skipping")
                    continue
                }
                val method: String = methodJson.asText()
                try {
                    enabledLocalizationMethods.add(LocalizationMethod.valueOf(method))
                } catch (e: IllegalArgumentException) {
                    LOGGER.error("Location '" + loc + "' has an unknown localizationMethod (" + method + "), skipping")
                    continue
                }
            }
        }
        // by default or if NO localization methods are explicitly enabled, enable ALL
        if (enabledLocalizationMethods.isEmpty()) {
            enabledLocalizationMethods.addAll(Arrays.asList(*LocalizationMethod.values()))
        }
        return enabledLocalizationMethods
    }

    /**
     * Creates a [Map] of Monitors used by [TrafficMonitorWatcher] to pull TrConfigs.
     *
     * @param trconfig.monitors
     * the monitors section of the TrafficRouter Configuration
     * @return void
     * @throws JsonUtilsException, ParseException
     */
    @Throws(JsonUtilsException::class, ParseException::class)
    private fun parseMonitorConfig(monitors: JsonNode?) {
        val monitorList: MutableList<String> = ArrayList()
        for (jo: JsonNode in monitors!!) {
            val fqdn: String? = JsonUtils.getString(jo, "fqdn")
            val port: Int = JsonUtils.optInt(jo, "port", 80)
            val status: String? = JsonUtils.getString(jo, "status")
            if (("ONLINE" == status)) {
                monitorList.add(fqdn + ":" + port)
            }
        }
        if (monitorList.isEmpty()) {
            throw ParseException("Unable to locate any ONLINE monitors in the TrConfig: " + monitors)
        }
        TrafficMonitorWatcher.Companion.setOnlineMonitors(monitorList)
    }

    /**
     * Returns the time stamp (seconds since the epoch) of the TrConfig snapshot.
     *
     * @param trconfig.stats
     * the stats section of the TrafficRouter Configuration
     * @return long
     * @throws JsonUtilsException
     */
    @Throws(JsonUtilsException::class)
    private fun getSnapshotTimestamp(stats: JsonNode?): Long {
        return JsonUtils.getLong(stats, "date")
    }

    fun setFederationsWatcher(federationsWatcher: FederationsWatcher?) {
        this.federationsWatcher = federationsWatcher
    }

    fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    private fun parseRequestHeaders(requestHeaders: JsonNode?): MutableSet<String?> {
        val headers: MutableSet<String?> = HashSet()
        if (requestHeaders == null) {
            return headers
        }
        for (header: JsonNode? in requestHeaders) {
            if (header != null) {
                headers.add(header.asText())
            } else {
                LOGGER.warn("Failed parsing request header from config")
            }
        }
        return headers
    }

    fun setSteeringWatcher(steeringWatcher: SteeringWatcher?) {
        this.steeringWatcher = steeringWatcher
    }

    fun setLetsEncryptDnsChallengeWatcher(letsEncryptDnsChallengeWatcher: LetsEncryptDnsChallengeWatcher?) {
        this.letsEncryptDnsChallengeWatcher = letsEncryptDnsChallengeWatcher
    }

    fun setCertificatesPoller(certificatesPoller: CertificatesPoller?) {
        this.certificatesPoller = certificatesPoller
    }

    fun cancelProcessConfig() {
        if (isProcessing.get()) {
            cancelled.set(true)
        }
    }

    val isProcessingConfig: Boolean
        get() {
            return isProcessing.get()
        }

    private fun getEdgeTrafficRouterLocationMap(jo: JsonNode): Map<String?, Location> {
        val locations: MutableMap<String?, Location> = HashMap(jo.size())
        val locs: Iterator<String> = jo.fieldNames()
        while (locs.hasNext()) {
            val loc: String = locs.next()
            try {
                val locJo: JsonNode? = JsonUtils.getJsonNode(jo, loc)
                locations.put(
                    loc,
                    Location(
                        loc,
                        Geolocation(JsonUtils.getDouble(locJo, "latitude"), JsonUtils.getDouble(locJo, "longitude"))
                    )
                )
            } catch (e: JsonUtilsException) {
                LOGGER.warn(e, e)
            }
        }
        return locations
    }

    @Throws(JsonUtilsException::class)
    private fun parseEdgeTrafficRouterLocations(jo: JsonNode, cacheRegister: CacheRegister) {
        val locationKey: String = "location"
        val trafficRouterJo: JsonNode? = JsonUtils.getJsonNode(jo, "contentRouters")
        val locations: MutableMap<Geolocation?, TrafficRouterLocation> = HashMap()
        val trafficRouterLocJo: JsonNode? = jo.get("trafficRouterLocations")
        if (trafficRouterLocJo == null) {
            LOGGER.warn("No trafficRouterLocations key found in configuration; unable to configure localized traffic routers")
            return
        }
        val allLocations: Map<String?, Location> = getEdgeTrafficRouterLocationMap(trafficRouterLocJo)
        val trafficRouterNames: Iterator<String> = trafficRouterJo!!.fieldNames()
        while (trafficRouterNames.hasNext()) {
            val trafficRouterName: String = trafficRouterNames.next()
            val trafficRouter: JsonNode = trafficRouterJo.get(trafficRouterName)

            // define here to log invalid ip/ip6 input on catch below
            var ip: String? = null
            var ip6: String? = null
            try {
                val trLoc: String? = JsonUtils.getString(trafficRouter, locationKey)
                val cl: Location? = allLocations.get(trLoc)
                if (cl != null) {
                    var trafficRouterLocation: TrafficRouterLocation? = locations.get(cl.getGeolocation())
                    if (trafficRouterLocation == null) {
                        trafficRouterLocation = TrafficRouterLocation(trLoc, cl.getGeolocation())
                        locations.put(cl.getGeolocation(), trafficRouterLocation)
                    }
                    val status: JsonNode? = trafficRouter.get("status")
                    if (status == null || (!("ONLINE" == status.asText()) && !("REPORTED" == status.asText()))) {
                        LOGGER.warn(
                            String.format(
                                "Skipping Edge Traffic Router %s due to %s status",
                                trafficRouterName,
                                status
                            )
                        )
                        continue
                    } else {
                        LOGGER.info(
                            String.format(
                                "Edge Traffic Router %s %s @ %s; %s",
                                status,
                                trafficRouterName,
                                trLoc,
                                cl.getGeolocation().toString()
                            )
                        )
                    }
                    val edgeTrafficRouter: Node = Node(trafficRouterName, trafficRouterName, optInt(jo, "hashCount"))
                    ip = JsonUtils.getString(trafficRouter, "ip")
                    ip6 = optString(trafficRouter, "ip6")
                    edgeTrafficRouter.setFqdn(JsonUtils.getString(trafficRouter, "fqdn"))
                    edgeTrafficRouter.setPort(JsonUtils.getInt(trafficRouter, "port"))
                    edgeTrafficRouter.setIpAddress(ip, ip6, 0)
                    trafficRouterLocation.addTrafficRouter(trafficRouterName, edgeTrafficRouter)
                } else {
                    LOGGER.error("No Location found for " + trLoc + "; unable to use Edge Traffic Router " + trafficRouterName)
                }
            } catch (e: JsonUtilsException) {
                LOGGER.warn(e, e)
            } catch (ex: UnknownHostException) {
                LOGGER.warn(String.format("%s; input was ip=%s, ip6=%s", ex, ip, ip6), ex)
            }
        }
        cacheRegister.setEdgeTrafficRouterLocations(locations.values)
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger(ConfigHandler::class.java)
        private var lastSnapshotTimestamp: Long = 0
        private val configSync: Any = Any()
        var deliveryServicesKey: String = "deliveryServices"
        var topologiesKey: String = "topologies"
        private val NEUSTAR_POLLING_URL: String = "neustar.polling.url"
        private val NEUSTAR_POLLING_INTERVAL: String = "neustar.polling.interval"
        private val LOCALIZATION_METHODS: String = "localizationMethods"
    }
}