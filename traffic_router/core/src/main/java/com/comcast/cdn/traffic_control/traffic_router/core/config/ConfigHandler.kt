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

import com.comcast.cdn.traffic_control.traffic_router.core.config.ConfigHandler
import com.comcast.cdn.traffic_control.traffic_router.core.config.ParseException
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallengeWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Location
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node
import com.comcast.cdn.traffic_control.traffic_router.core.edge.TrafficRouterLocation
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIp
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpConfigUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.DeepNetworkUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.loc.GeolocationDatabaseUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.request.RequestMatcher
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesPoller
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesPublisher
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.io.IOException
import java.net.URL
import java.net.UnknownHostException
import java.util.Arrays
import java.util.Date
import java.util.Objects
import java.util.TreeSet
import java.util.concurrent.BlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.function.BiConsumer
import java.util.function.Consumer
import java.util.stream.Collectors
import java.util.stream.Stream

class ConfigHandler {
    private var trafficRouterManager: TrafficRouterManager? = null
    private var geolocationDatabaseUpdater: GeolocationDatabaseUpdater? = null
    private var statTracker: StatTracker? = null
    private var configDir: String? = null
    private var trafficRouterId: String? = null
    private var trafficOpsUtils: TrafficOpsUtils? = null
    private var networkUpdater: NetworkUpdater? = null
    private var deepNetworkUpdater: DeepNetworkUpdater? = null
    private var federationsWatcher: FederationsWatcher? = null
    private var regionalGeoUpdater: RegionalGeoUpdater? = null
    private var anonymousIpConfigUpdater: AnonymousIpConfigUpdater? = null
    private var anonymousIpDatabaseUpdater: AnonymousIpDatabaseUpdater? = null
    private var steeringWatcher: SteeringWatcher? = null
    private var letsEncryptDnsChallengeWatcher: LetsEncryptDnsChallengeWatcher? = null
    private var certificatesPoller: CertificatesPoller? = null
    private var certificatesPublisher: CertificatesPublisher? = null
    private var publishStatusQueue: BlockingQueue<Boolean?>? = null
    private val cancelled: AtomicBoolean? = AtomicBoolean(false)
    private val isProcessing: AtomicBoolean? = AtomicBoolean(false)
    fun getConfigDir(): String? {
        return configDir
    }

    fun getTrafficRouterId(): String? {
        return trafficRouterId
    }

    fun getGeolocationDatabaseUpdater(): GeolocationDatabaseUpdater? {
        return geolocationDatabaseUpdater
    }

    fun getNetworkUpdater(): NetworkUpdater? {
        return networkUpdater
    }

    fun getDeepNetworkUpdater(): DeepNetworkUpdater? {
        return deepNetworkUpdater
    }

    fun getRegionalGeoUpdater(): RegionalGeoUpdater? {
        return regionalGeoUpdater
    }

    fun getAnonymousIpConfigUpdater(): AnonymousIpConfigUpdater? {
        return anonymousIpConfigUpdater
    }

    fun getAnonymousIpDatabaseUpdater(): AnonymousIpDatabaseUpdater? {
        return anonymousIpDatabaseUpdater
    }

    @Throws(JsonUtilsException::class, IOException::class)
    fun processConfig(jsonStr: String?): Boolean {
        isProcessing.set(true)
        ConfigHandler.Companion.LOGGER.info("Entered processConfig")
        if (jsonStr == null) {
            trafficRouterManager.setCacheRegister(null)
            cancelled.set(false)
            isProcessing.set(false)
            publishStatusQueue.clear()
            ConfigHandler.Companion.LOGGER.info("Exiting processConfig: No json data to process")
            return false
        }
        var date: Date?
        synchronized(ConfigHandler.Companion.configSync) {
            val mapper = ObjectMapper()
            val jo = mapper.readTree(jsonStr)
            val config = JsonUtils.getJsonNode(jo, "config")
            val stats = JsonUtils.getJsonNode(jo, "stats")
            val sts = getSnapshotTimestamp(stats)
            date = Date(sts * 1000L)
            if (sts <= ConfigHandler.Companion.getLastSnapshotTimestamp()) {
                cancelled.set(false)
                isProcessing.set(false)
                publishStatusQueue.clear()
                ConfigHandler.Companion.LOGGER.info("Exiting processConfig: Incoming TrConfig snapshot timestamp (" + sts + ") is older or equal to the loaded timestamp (" + ConfigHandler.Companion.getLastSnapshotTimestamp() + "); unable to process")
                return false
            }
            try {
                parseGeolocationConfig(config)
                parseCoverageZoneNetworkConfig(config)
                parseDeepCoverageZoneNetworkConfig(config)
                parseRegionalGeoConfig(jo)
                parseAnonymousIpConfig(jo)
                val cacheRegister = CacheRegister()
                val deliveryServicesJson = JsonUtils.getJsonNode(jo, ConfigHandler.Companion.deliveryServicesKey)
                cacheRegister.trafficRouters = JsonUtils.getJsonNode(jo, "contentRouters")
                cacheRegister.config = config
                cacheRegister.stats = stats
                parseTrafficOpsConfig(config, stats)
                val deliveryServiceMap =
                    parseDeliveryServiceConfig(JsonUtils.getJsonNode(jo, ConfigHandler.Companion.deliveryServicesKey))
                parseCertificatesConfig(config)
                certificatesPublisher.setDeliveryServicesJson(deliveryServicesJson)
                val deliveryServices = ArrayList<DeliveryService?>()
                if (deliveryServiceMap != null && !deliveryServiceMap.values.isEmpty()) {
                    deliveryServices.addAll(deliveryServiceMap.values)
                }
                if (deliveryServiceMap != null && !deliveryServiceMap.values.isEmpty()) {
                    certificatesPublisher.setDeliveryServices(deliveryServices)
                }
                certificatesPoller.restart()
                val httpsDeliveryServices =
                    deliveryServices.stream().filter { ds: DeliveryService? -> !ds.isDns() && ds.isSslEnabled() }
                        .collect(Collectors.toList())
                httpsDeliveryServices.forEach(Consumer { ds: DeliveryService? -> ConfigHandler.Companion.LOGGER.info("Checking for certificate for " + ds.getId()) })
                if (!httpsDeliveryServices.isEmpty()) {
                    try {
                        publishStatusQueue.put(true)
                    } catch (e: InterruptedException) {
                        ConfigHandler.Companion.LOGGER.warn(
                            "Failed to notify certificates publisher we're waiting for certificates",
                            e
                        )
                    }
                    while (!cancelled.get() && !publishStatusQueue.isEmpty()) {
                        try {
                            ConfigHandler.Companion.LOGGER.info(
                                "Waiting for https certificates to support new config " + String.format(
                                    "%x",
                                    publishStatusQueue.hashCode()
                                )
                            )
                            Thread.sleep(1000L)
                        } catch (t: Throwable) {
                            ConfigHandler.Companion.LOGGER.warn(
                                "Interrupted while waiting for status on publishing ssl certs",
                                t
                            )
                        }
                    }
                }
                if (cancelled.get()) {
                    cancelled.set(false)
                    isProcessing.set(false)
                    publishStatusQueue.clear()
                    ConfigHandler.Companion.LOGGER.info("Exiting processConfig: processing of config with timestamp $date was cancelled")
                    return false
                }
                parseDeliveryServiceMatchSets(deliveryServicesJson, deliveryServiceMap, cacheRegister)
                parseLocationConfig(JsonUtils.getJsonNode(jo, "edgeLocations"), cacheRegister)
                parseEdgeTrafficRouterLocations(jo, cacheRegister)
                parseCacheConfig(JsonUtils.getJsonNode(jo, "contentServers"), cacheRegister)
                if (jo.has(ConfigHandler.Companion.topologiesKey)) {
                    parseTopologyConfig(
                        JsonUtils.getJsonNode(jo, ConfigHandler.Companion.topologiesKey),
                        deliveryServiceMap,
                        cacheRegister
                    )
                }
                parseMonitorConfig(JsonUtils.getJsonNode(jo, "monitors"))
                federationsWatcher.configure(config)
                steeringWatcher.configure(config)
                letsEncryptDnsChallengeWatcher.configure(config)
                trafficRouterManager.setCacheRegister(cacheRegister)
                trafficRouterManager.getNameServer().setEcsEnable(JsonUtils.optBoolean(config, "ecsEnable", false))
                trafficRouterManager.getNameServer().ecsEnabledDses =
                    deliveryServices.stream().filter { obj: DeliveryService? -> obj.isEcsEnabled() }
                        .collect(Collectors.toSet())
                trafficRouterManager.getTrafficRouter().requestHeaders = parseRequestHeaders(config["requestHeaders"])
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
				 */NetworkNode.Companion.getInstance().clearLocations()
                NetworkNode.Companion.getDeepInstance().clearLocations(true)
                ConfigHandler.Companion.setLastSnapshotTimestamp(sts)
            } catch (e: ParseException) {
                isProcessing.set(false)
                cancelled.set(false)
                publishStatusQueue.clear()
                ConfigHandler.Companion.LOGGER.error(
                    "Exiting processConfig: Failed to process config for snapshot from $date",
                    e
                )
                return false
            }
        }
        ConfigHandler.Companion.LOGGER.info("Exit: processConfig, successfully applied snapshot from $date")
        isProcessing.set(false)
        cancelled.set(false)
        publishStatusQueue.clear()
        return true
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun setConfigDir(configDir: String?) {
        this.configDir = configDir
    }

    fun setTrafficRouterId(traffictRouterId: String?) {
        trafficRouterId = traffictRouterId
    }

    fun setGeolocationDatabaseUpdater(geolocationDatabaseUpdater: GeolocationDatabaseUpdater?) {
        this.geolocationDatabaseUpdater = geolocationDatabaseUpdater
    }

    fun setNetworkUpdater(nu: NetworkUpdater?) {
        networkUpdater = nu
    }

    fun setDeepNetworkUpdater(dnu: DeepNetworkUpdater?) {
        deepNetworkUpdater = dnu
    }

    fun setRegionalGeoUpdater(regionalGeoUpdater: RegionalGeoUpdater?) {
        this.regionalGeoUpdater = regionalGeoUpdater
    }

    fun setAnonymousIpConfigUpdater(anonymousIpConfigUpdater: AnonymousIpConfigUpdater?) {
        this.anonymousIpConfigUpdater = anonymousIpConfigUpdater
    }

    fun setAnonymousIpDatabaseUpdater(anonymousIpDatabaseUpdater: AnonymousIpDatabaseUpdater?) {
        this.anonymousIpDatabaseUpdater = anonymousIpDatabaseUpdater
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
        if (stats.has("tm_host")) {
            trafficOpsUtils.setHostname(JsonUtils.getString(stats, "tm_host"))
        } else if (stats.has("to_host")) {
            trafficOpsUtils.setHostname(JsonUtils.getString(stats, "to_host"))
        } else {
            throw JsonUtilsException("Unable to find to_host or tm_host in stats section of TrConfig; unable to build TrafficOps URLs")
        }
        trafficOpsUtils.setCdnName(JsonUtils.optString(stats, "CDN_name", null))
        trafficOpsUtils.setConfig(config)
    }

    /**
     * Parses the cache information from the configuration and updates the [CacheRegister].
     *
     * @param trConfig
     * the [TrafficRouterConfiguration]
     * @throws JsonUtilsException, ParseException
     */
    @Throws(JsonUtilsException::class, ParseException::class)
    private fun parseCacheConfig(contentServers: JsonNode?, cacheRegister: CacheRegister?) {
        val map: MutableMap<String?, Cache?> = HashMap()
        val statMap: MutableMap<String?, MutableList<String?>?> = HashMap()
        val nodeIter = contentServers.fieldNames()
        while (nodeIter.hasNext()) {
            val node = nodeIter.next()
            val jo = JsonUtils.getJsonNode(contentServers, node)
            val loc = cacheRegister.getCacheLocation(JsonUtils.getString(jo, "locationId"))
            if (loc != null) {
                var hashId = node
                // not only must we check for the key, but also if it's null; problems with consistent hashing can arise if we use a null value as the hashId
                if (jo.has("hashId") && jo["hashId"].textValue() != null) {
                    hashId = jo["hashId"].textValue()
                }
                val cache = Cache(node, hashId, optInt(jo, "hashCount"), loc.geolocation)
                cache.fqdn = JsonUtils.getString(jo, "fqdn")
                cache.port = JsonUtils.getInt(jo, "port")
                if (jo.has("capabilities")) {
                    val capabilities: MutableSet<String?> = HashSet()
                    val capabilitiesNode = jo["capabilities"]
                    if (!capabilitiesNode.isArray) {
                        ConfigHandler.Companion.LOGGER.error("Server '$hashId' has malformed capabilities. Disregarding.")
                    } else {
                        capabilitiesNode.forEach(Consumer { capabilityNode: JsonNode? ->
                            val capability = capabilityNode.asText()
                            if (!capability.isEmpty()) {
                                capabilities.add(capability)
                            }
                        })
                    }
                    cache.addCapabilities(capabilities)
                }
                val ip = JsonUtils.getString(jo, "ip")
                val ip6: String = optString(jo, "ip6")
                try {
                    cache.setIpAddress(ip, ip6, 0)
                } catch (e: UnknownHostException) {
                    ConfigHandler.Companion.LOGGER.warn("$e : $ip")
                }
                if (jo.has(ConfigHandler.Companion.deliveryServicesKey)) {
                    val references: MutableList<DeliveryServiceReference?> = ArrayList()
                    val dsJos: JsonNode = jo.get(ConfigHandler.Companion.deliveryServicesKey)
                    val dsIter = dsJos.fieldNames()
                    while (dsIter.hasNext()) {
                        /* technically this could be more than just a string or array,
						 * but, as we only have had those two types, let's not worry about the future
						 */
                        val ds = dsIter.next()
                        val dso = dsJos[ds]
                        var dsNames = statMap[ds]
                        if (dsNames == null) {
                            dsNames = ArrayList()
                        }
                        if (dso.isArray) {
                            if (dso != null && dso.size() > 0) {
                                var i = 0
                                for (nameNode in dso) {
                                    val name = nameNode.asText()
                                    if (i == 0) {
                                        references.add(DeliveryServiceReference(ds, name))
                                    }
                                    val tld: String = optString(cacheRegister.getConfig(), "domain_name")
                                    val dsName = getDsName(name, tld)
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
                        statMap[ds] = dsNames
                    }
                    cache.deliveryServices = references
                }
                loc.addCache(cache)
                map[cache.id] = cache
            }
        }
        cacheRegister.setCacheMap(map)
        statTracker.initialize(statMap, cacheRegister)
    }

    @Throws(JsonUtilsException::class)
    private fun parseDeliveryServiceConfig(allDeliveryServices: JsonNode?): MutableMap<String?, DeliveryService?>? {
        val deliveryServiceMap: MutableMap<String?, DeliveryService?> = HashMap()
        val deliveryServiceIter = allDeliveryServices.fieldNames()
        while (deliveryServiceIter.hasNext()) {
            val deliveryServiceId = deliveryServiceIter.next()
            val deliveryServiceJson = JsonUtils.getJsonNode(allDeliveryServices, deliveryServiceId)
            val deliveryService = DeliveryService(deliveryServiceId, deliveryServiceJson)
            var isDns = false
            val matchsets = JsonUtils.getJsonNode(deliveryServiceJson, "matchsets")
            for (matchset in matchsets) {
                val protocol = JsonUtils.getString(matchset, "protocol")
                if ("DNS" == protocol) {
                    isDns = true
                }
            }
            deliveryService.isDns = isDns
            deliveryServiceMap[deliveryServiceId] = deliveryService
        }
        return deliveryServiceMap
    }

    private fun getDsName(name: String?, tld: String?): String? {
        return if (name.endsWith(tld)) name.replace("^.*?\\.".toRegex(), "") else name
    }

    private fun parseTopologyConfig(
        allTopologies: JsonNode?,
        deliveryServiceMap: MutableMap<String?, DeliveryService?>?,
        cacheRegister: CacheRegister?
    ) {
        val topologyMap: MutableMap<String?, MutableList<String?>?> = HashMap()
        val statMap: MutableMap<String?, MutableList<String?>?> = HashMap()
        val tld: String = optString(cacheRegister.getConfig(), "domain_name")
        allTopologies.fieldNames().forEachRemaining { topologyName: String? ->
            val nodes: MutableList<String?> = ArrayList()
            allTopologies.get(topologyName)["nodes"].forEach(Consumer { cache: JsonNode? -> nodes.add(cache.textValue()) })
            topologyMap[topologyName] = nodes
        }
        deliveryServiceMap.forEach(BiConsumer { xmlId: String?, ds: DeliveryService? ->
            val dsReferences: MutableList<DeliveryServiceReference?> = ArrayList()
            val dsNames: MutableList<String?> = ArrayList() // for stats
            Stream.of(ds.getTopology())
                .filter { topologyName: String? -> !Objects.isNull(topologyName) && topologyMap.containsKey(topologyName) }
                .flatMap { topologyName: String? ->
                    statMap[ds.getId()] = dsNames
                    topologyMap[topologyName].stream()
                }
                .flatMap { node: String? -> cacheRegister.getCacheLocation(node).caches.stream() }
                .filter { cache: Cache? -> ds.hasRequiredCapabilities(cache.getCapabilities()) }
                .forEach { cache: Cache? ->
                    cacheRegister.getDeliveryServiceMatchers(ds).stream()
                        .flatMap { deliveryServiceMatcher: DeliveryServiceMatcher? ->
                            deliveryServiceMatcher.getRequestMatchers().stream()
                        }
                        .map { requestMatcher: RequestMatcher? -> requestMatcher.getPattern().pattern() }
                        .forEach { pattern: String? ->
                            val remap = ds.getRemap(pattern)
                            val fqdn = if (pattern.contains(".*") && !ds.isDns()) cache.getId() + "." + remap else remap
                            dsNames.add(getDsName(fqdn, tld))
                            if (remap != if (ds.isDns()) ds.getRoutingName() + "." + ds.getDomain() else ds.getDomain()) {
                                return@forEach
                            }
                            try {
                                dsReferences.add(DeliveryServiceReference(ds.getId(), fqdn))
                            } catch (e: ParseException) {
                                ConfigHandler.Companion.LOGGER.error(
                                    "Unable to create a DeliveryServiceReference from DeliveryService '" + ds.getId() + "'",
                                    e
                                )
                            }
                        }
                    cache.setDeliveryServices(dsReferences)
                }
        })
        statTracker.initialize(statMap, cacheRegister)
    }

    @Throws(JsonUtilsException::class)
    private fun parseDeliveryServiceMatchSets(
        allDeliveryServices: JsonNode?,
        deliveryServiceMap: MutableMap<String?, DeliveryService?>?,
        cacheRegister: CacheRegister?
    ) {
        val deliveryServiceMatchers = TreeSet<DeliveryServiceMatcher?>()
        val config = cacheRegister.getConfig()
        val regexSuperhackEnabled = JsonUtils.optBoolean(config, "confighandler.regex.superhack.enabled", true)
        val deliveryServiceIds = allDeliveryServices.fieldNames()
        while (deliveryServiceIds.hasNext()) {
            val deliveryServiceId = deliveryServiceIds.next()
            val deliveryServiceJson = JsonUtils.getJsonNode(allDeliveryServices, deliveryServiceId)
            val matchsets = JsonUtils.getJsonNode(deliveryServiceJson, "matchsets")
            val deliveryService = deliveryServiceMap.get(deliveryServiceId)
            for (i in 0 until matchsets.size()) {
                val matchset = matchsets[i]
                val deliveryServiceMatcher = DeliveryServiceMatcher(deliveryService)
                deliveryServiceMatchers.add(deliveryServiceMatcher)
                val list = JsonUtils.getJsonNode(matchset, "matchlist")
                for (j in 0 until list.size()) {
                    val matcherJo = list[j]
                    val type = DeliveryServiceMatcher.Type.valueOf(JsonUtils.getString(matcherJo, "match-type"))
                    val target: String = optString(matcherJo, "target")
                    var regex = JsonUtils.getString(matcherJo, "regex")
                    if (regexSuperhackEnabled && i == 0 && j == 0 && type == DeliveryServiceMatcher.Type.HOST) {
                        regex = regex.replaceFirst("^\\.\\*\\\\\\.".toRegex(), "(.*\\\\.|^)")
                    }
                    deliveryServiceMatcher.addMatch(type, regex, target)
                }
            }
        }
        cacheRegister.setDeliveryServiceMap(deliveryServiceMap)
        cacheRegister.setDeliveryServiceMatchers(deliveryServiceMatchers)
        initGeoFailedRedirect(deliveryServiceMap, cacheRegister)
    }

    private fun initGeoFailedRedirect(dsMap: MutableMap<String?, DeliveryService?>?, cacheRegister: CacheRegister?) {
        val itr = dsMap.keys.iterator()
        while (itr.hasNext()) {
            val ds = dsMap.get(itr.next())
            //check if it's relative path or not
            val rurl = ds.getGeoRedirectUrl() ?: continue
            try {
                val idx = rurl.indexOf("://")
                if (idx < 0) {
                    //this is a relative url, belongs to this ds
                    ds.setGeoRedirectUrlType("DS_URL")
                    continue
                }
                //this is a url with protocol, must check further
                //first, parse the url, if url invalid it will throw Exception
                val url = URL(rurl)

                //make a fake HTTPRequest for the redirect url
                val req = HTTPRequest(url)
                ds.setGeoRedirectFile(url.file)
                //try select the ds by the redirect fake HTTPRequest
                val rds = cacheRegister.getDeliveryService(req)
                if (rds == null || rds.id !== ds.getId()) {
                    //the redirect url not belongs to this ds
                    ds.setGeoRedirectUrlType("NOT_DS_URL")
                    continue
                }
                ds.setGeoRedirectUrlType("DS_URL")
            } catch (e: Exception) {
                ConfigHandler.Companion.LOGGER.error("fatal error, failed to init NGB redirect with Exception: " + e.message)
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
        var pollingUrlKey = "geolocation.polling.url"
        if (config.has("alt.geolocation.polling.url")) {
            pollingUrlKey = "alt.geolocation.polling.url"
        }
        getGeolocationDatabaseUpdater().setDataBaseURL(
            JsonUtils.getString(config, pollingUrlKey),
            optLong(config, "geolocation.polling.interval")
        )
        if (config.has(ConfigHandler.Companion.NEUSTAR_POLLING_URL)) {
            System.setProperty(
                ConfigHandler.Companion.NEUSTAR_POLLING_URL,
                JsonUtils.getString(config, ConfigHandler.Companion.NEUSTAR_POLLING_URL)
            )
        }
        if (config.has(ConfigHandler.Companion.NEUSTAR_POLLING_INTERVAL)) {
            System.setProperty(
                ConfigHandler.Companion.NEUSTAR_POLLING_INTERVAL,
                JsonUtils.getString(config, ConfigHandler.Companion.NEUSTAR_POLLING_INTERVAL)
            )
        }
    }

    private fun parseCertificatesConfig(config: JsonNode?) {
        val pollingInterval = "certificates.polling.interval"
        if (config.has(pollingInterval)) {
            try {
                System.setProperty(pollingInterval, JsonUtils.getString(config, pollingInterval))
            } catch (e: Exception) {
                ConfigHandler.Companion.LOGGER.warn("Failed to set system property " + pollingInterval + " from configuration object: " + e.message)
            }
        }
    }

    @Throws(JsonUtilsException::class)
    private fun parseAnonymousIpConfig(jo: JsonNode?) {
        val anonymousPollingUrl = "anonymousip.polling.url"
        val anonymousPollingInterval = "anonymousip.polling.interval"
        val anonymousPolicyConfiguration = "anonymousip.policy.configuration"
        val config = JsonUtils.getJsonNode(jo, "config")
        val configUrl = JsonUtils.optString(config, anonymousPolicyConfiguration, null)
        val databaseUrl = JsonUtils.optString(config, anonymousPollingUrl, null)
        if (configUrl == null) {
            ConfigHandler.Companion.LOGGER.info("$anonymousPolicyConfiguration not configured; stopping service updater and disabling feature")
            getAnonymousIpConfigUpdater().stopServiceUpdater()
            AnonymousIp.Companion.getCurrentConfig().enabled = false
            return
        }
        if (databaseUrl == null) {
            ConfigHandler.Companion.LOGGER.info("$anonymousPollingUrl not configured; stopping service updater and disabling feature")
            getAnonymousIpDatabaseUpdater().stopServiceUpdater()
            AnonymousIp.Companion.getCurrentConfig().enabled = false
            return
        }
        if (jo.has(ConfigHandler.Companion.deliveryServicesKey)) {
            val dss = JsonUtils.getJsonNode(jo, ConfigHandler.Companion.deliveryServicesKey)
            val dsNames = dss.fieldNames()
            while (dsNames.hasNext()) {
                val ds = dsNames.next()
                val dsNode = JsonUtils.getJsonNode(dss, ds)
                if (optString(dsNode, "anonymousBlockingEnabled") == "true") {
                    val interval: Long = optLong(config, anonymousPollingInterval)
                    getAnonymousIpConfigUpdater().setDataBaseURL(configUrl, interval)
                    getAnonymousIpDatabaseUpdater().setDataBaseURL(databaseUrl, interval)
                    AnonymousIp.Companion.getCurrentConfig().enabled = true
                    ConfigHandler.Companion.LOGGER.debug("Anonymous Blocking in use, scheduling service updaters and enabling feature")
                    return
                }
            }
        }
        ConfigHandler.Companion.LOGGER.debug("No DS using anonymous ip blocking - disabling feature")
        getAnonymousIpConfigUpdater().cancelServiceUpdater()
        getAnonymousIpDatabaseUpdater().cancelServiceUpdater()
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
        getNetworkUpdater().setDataBaseURL(
            JsonUtils.getString(config, "coveragezone.polling.url"),
            optLong(config, "coveragezone.polling.interval")
        )
    }

    @Throws(JsonUtilsException::class)
    private fun parseDeepCoverageZoneNetworkConfig(config: JsonNode?) {
        getDeepNetworkUpdater().setDataBaseURL(
            JsonUtils.optString(config, "deepcoveragezone.polling.url", null),
            optLong(config, "deepcoveragezone.polling.interval")
        )
    }

    @Throws(JsonUtilsException::class)
    private fun parseRegionalGeoConfig(jo: JsonNode?) {
        val config = JsonUtils.getJsonNode(jo, "config")
        val url = JsonUtils.optString(config, "regional_geoblock.polling.url", null)
        if (url == null) {
            ConfigHandler.Companion.LOGGER.info("regional_geoblock.polling.url not configured; stopping service updater")
            getRegionalGeoUpdater().stopServiceUpdater()
            return
        }
        if (jo.has(ConfigHandler.Companion.deliveryServicesKey)) {
            val dss: JsonNode = jo.get(ConfigHandler.Companion.deliveryServicesKey)
            for (ds in dss) {
                if (ds.has("regionalGeoBlocking") && JsonUtils.getString(ds, "regionalGeoBlocking") == "true") {
                    val interval: Long = optLong(config, "regional_geoblock.polling.interval")
                    getRegionalGeoUpdater().setDataBaseURL(url, interval)
                    return
                }
            }
        }
        getRegionalGeoUpdater().cancelServiceUpdater()
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
    private fun parseLocationConfig(locationsJo: JsonNode?, cacheRegister: CacheRegister?) {
        val locations: MutableSet<CacheLocation?> = HashSet(locationsJo.size())
        val locIter = locationsJo.fieldNames()
        while (locIter.hasNext()) {
            val loc = locIter.next()
            val jo = JsonUtils.getJsonNode(locationsJo, loc)
            var backupCacheGroups: MutableList<String?>? = null
            var useClosestOnBackupFailure = true
            if (jo != null && jo.has("backupLocations")) {
                val backupConfigJson = JsonUtils.getJsonNode(jo, "backupLocations")
                backupCacheGroups = ArrayList()
                if (backupConfigJson.has("list")) {
                    for (cacheGroup in JsonUtils.getJsonNode(backupConfigJson, "list")) {
                        backupCacheGroups.add(cacheGroup.asText())
                    }
                    useClosestOnBackupFailure = JsonUtils.optBoolean(backupConfigJson, "fallbackToClosest", false)
                }
            }
            val enabledLocalizationMethods = parseLocalizationMethods(loc, jo)
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
                ConfigHandler.Companion.LOGGER.warn(e, e)
            }
        }
        cacheRegister.setConfiguredLocations(locations)
    }

    @Throws(JsonUtilsException::class)
    private fun parseLocalizationMethods(loc: String?, jo: JsonNode?): MutableSet<LocalizationMethod?>? {
        val enabledLocalizationMethods: MutableSet<LocalizationMethod?> = HashSet()
        if (jo != null && jo.hasNonNull(ConfigHandler.Companion.LOCALIZATION_METHODS) && JsonUtils.getJsonNode(
                jo,
                ConfigHandler.Companion.LOCALIZATION_METHODS
            ).isArray
        ) {
            val localizationMethodsJson = JsonUtils.getJsonNode(jo, ConfigHandler.Companion.LOCALIZATION_METHODS)
            for (methodJson in localizationMethodsJson) {
                if (methodJson.isNull || !methodJson.isTextual) {
                    ConfigHandler.Companion.LOGGER.error("Location '$loc' has a non-string localizationMethod, skipping")
                    continue
                }
                val method = methodJson.asText()
                try {
                    enabledLocalizationMethods.add(LocalizationMethod.valueOf(method))
                } catch (e: IllegalArgumentException) {
                    ConfigHandler.Companion.LOGGER.error("Location '$loc' has an unknown localizationMethod ($method), skipping")
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
        val monitorList: MutableList<String?> = ArrayList()
        for (jo in monitors) {
            val fqdn = JsonUtils.getString(jo, "fqdn")
            val port = JsonUtils.optInt(jo, "port", 80)
            val status = JsonUtils.getString(jo, "status")
            if ("ONLINE" == status) {
                monitorList.add("$fqdn:$port")
            }
        }
        if (monitorList.isEmpty()) {
            throw ParseException("Unable to locate any ONLINE monitors in the TrConfig: $monitors")
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

    fun getStatTracker(): StatTracker? {
        return statTracker
    }

    fun setStatTracker(statTracker: StatTracker?) {
        this.statTracker = statTracker
    }

    fun setFederationsWatcher(federationsWatcher: FederationsWatcher?) {
        this.federationsWatcher = federationsWatcher
    }

    fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    private fun parseRequestHeaders(requestHeaders: JsonNode?): MutableSet<String?>? {
        val headers: MutableSet<String?> = HashSet()
        if (requestHeaders == null) {
            return headers
        }
        for (header in requestHeaders) {
            if (header != null) {
                headers.add(header.asText())
            } else {
                ConfigHandler.Companion.LOGGER.warn("Failed parsing request header from config")
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

    fun getCertificatesPublisher(): CertificatesPublisher? {
        return certificatesPublisher
    }

    fun setCertificatesPublisher(certificatesPublisher: CertificatesPublisher?) {
        this.certificatesPublisher = certificatesPublisher
    }

    fun getPublishStatusQueue(): BlockingQueue<Boolean?>? {
        return publishStatusQueue
    }

    fun setPublishStatusQueue(publishStatusQueue: BlockingQueue<Boolean?>?) {
        this.publishStatusQueue = publishStatusQueue
    }

    fun cancelProcessConfig() {
        if (isProcessing.get()) {
            cancelled.set(true)
        }
    }

    fun isProcessingConfig(): Boolean {
        return isProcessing.get()
    }

    private fun getEdgeTrafficRouterLocationMap(jo: JsonNode?): MutableMap<String?, Location?>? {
        val locations: MutableMap<String?, Location?> = HashMap(jo.size())
        val locs = jo.fieldNames()
        while (locs.hasNext()) {
            val loc = locs.next()
            try {
                val locJo = JsonUtils.getJsonNode(jo, loc)
                locations[loc] = Location(
                    loc,
                    Geolocation(JsonUtils.getDouble(locJo, "latitude"), JsonUtils.getDouble(locJo, "longitude"))
                )
            } catch (e: JsonUtilsException) {
                ConfigHandler.Companion.LOGGER.warn(e, e)
            }
        }
        return locations
    }

    @Throws(JsonUtilsException::class)
    private fun parseEdgeTrafficRouterLocations(jo: JsonNode?, cacheRegister: CacheRegister?) {
        val locationKey = "location"
        val trafficRouterJo = JsonUtils.getJsonNode(jo, "contentRouters")
        val locations: MutableMap<Geolocation?, TrafficRouterLocation?> = HashMap()
        val trafficRouterLocJo = jo.get("trafficRouterLocations")
        if (trafficRouterLocJo == null) {
            ConfigHandler.Companion.LOGGER.warn("No trafficRouterLocations key found in configuration; unable to configure localized traffic routers")
            return
        }
        val allLocations = getEdgeTrafficRouterLocationMap(trafficRouterLocJo)
        val trafficRouterNames = trafficRouterJo.fieldNames()
        while (trafficRouterNames.hasNext()) {
            val trafficRouterName = trafficRouterNames.next()
            val trafficRouter = trafficRouterJo[trafficRouterName]

            // define here to log invalid ip/ip6 input on catch below
            var ip: String? = null
            var ip6: String? = null
            try {
                val trLoc = JsonUtils.getString(trafficRouter, locationKey)
                val cl = allLocations.get(trLoc)
                if (cl != null) {
                    var trafficRouterLocation = locations[cl.geolocation]
                    if (trafficRouterLocation == null) {
                        trafficRouterLocation = TrafficRouterLocation(trLoc, cl.geolocation)
                        locations[cl.geolocation] = trafficRouterLocation
                    }
                    val status = trafficRouter["status"]
                    if (status == null || "ONLINE" != status.asText() && "REPORTED" != status.asText()) {
                        ConfigHandler.Companion.LOGGER.warn(
                            String.format(
                                "Skipping Edge Traffic Router %s due to %s status",
                                trafficRouterName,
                                status
                            )
                        )
                        continue
                    } else {
                        ConfigHandler.Companion.LOGGER.info(
                            String.format(
                                "Edge Traffic Router %s %s @ %s; %s",
                                status,
                                trafficRouterName,
                                trLoc,
                                cl.geolocation.toString()
                            )
                        )
                    }
                    val edgeTrafficRouter = Node(trafficRouterName, trafficRouterName, optInt(jo, "hashCount"))
                    ip = JsonUtils.getString(trafficRouter, "ip")
                    ip6 = optString(trafficRouter, "ip6")
                    edgeTrafficRouter.fqdn = JsonUtils.getString(trafficRouter, "fqdn")
                    edgeTrafficRouter.port = JsonUtils.getInt(trafficRouter, "port")
                    edgeTrafficRouter.setIpAddress(ip, ip6, 0)
                    trafficRouterLocation.addTrafficRouter(trafficRouterName, edgeTrafficRouter)
                } else {
                    ConfigHandler.Companion.LOGGER.error("No Location found for $trLoc; unable to use Edge Traffic Router $trafficRouterName")
                }
            } catch (e: JsonUtilsException) {
                ConfigHandler.Companion.LOGGER.warn(e, e)
            } catch (ex: UnknownHostException) {
                ConfigHandler.Companion.LOGGER.warn(String.format("%s; input was ip=%s, ip6=%s", ex, ip, ip6), ex)
            }
        }
        cacheRegister.setEdgeTrafficRouterLocations(locations.values)
    }

    companion object {
        private val LOGGER = Logger.getLogger(ConfigHandler::class.java)
        private const val lastSnapshotTimestamp: Long = 0
        private val configSync: Any? = Any()
        var deliveryServicesKey: String? = "deliveryServices"
        var topologiesKey: String? = "topologies"
        private val NEUSTAR_POLLING_URL: String? = "neustar.polling.url"
        private val NEUSTAR_POLLING_INTERVAL: String? = "neustar.polling.interval"
        private val LOCALIZATION_METHODS: String? = "localizationMethods"
        private fun getLastSnapshotTimestamp(): Long {
            return ConfigHandler.Companion.lastSnapshotTimestamp
        }

        private fun setLastSnapshotTimestamp(lastSnapshotTimestamp: Long) {
            ConfigHandler.Companion.lastSnapshotTimestamp = lastSnapshotTimestamp
        }
    }
}