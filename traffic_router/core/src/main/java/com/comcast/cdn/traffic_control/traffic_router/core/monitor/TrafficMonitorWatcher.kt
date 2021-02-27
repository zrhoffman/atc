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
package com.comcast.cdn.traffic_control.traffic_router.core.monitor

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
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.security.GeneralSecurityException
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
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import org.springframework.context.event.ContextClosedEvent
import java.io.*
import java.net.*
import java.util.*

class TrafficMonitorWatcher constructor() : ApplicationListener<ApplicationContextEvent?> {
    var stateUrl: String? = null
    var configUrl: String? = null
    private var monitorHosts: String? = null
    var pollingInterval: Int = 5000
    private var lastHostAttempt: Long = 0
    private var reloadPeriod: Long = (60 * 1000).toLong()
    var configHandler: ConfigHandler? = null
    var trafficRouterManager: TrafficRouterManager? = null
    var statusFile: String? = null
    var statusRefreshPeriod: Int = 0
    var configFile: String? = null
    var configRefreshPeriod: Int = 0
    private var monitorProperties: String? = null
    private var crUpdater: PeriodicResourceUpdater? = null
    private var stateUpdater: PeriodicResourceUpdater? = null
    var propertiesDirectory: Path? = null
    var databasesDirectory: Path? = null
    var stateHandler: AbstractUpdatable = object : AbstractUpdatable() {
        public override fun toString(): String {
            return "status listener"
        }

        @Synchronized
        public override fun update(jsonStr: String?): Boolean {
            try {
                val mapper: ObjectMapper = ObjectMapper()
                return trafficRouterManager!!.setState(mapper.readTree(jsonStr))
            } catch (e: JsonProcessingException) {
                LOGGER.warn("problem with json: ", e)
            } catch (e: IOException) {
                LOGGER.warn(e, e)
            }
            return false
        }

        public override fun noChange(): Boolean {
            try {
                trafficRouterManager!!.setState(null)
            } catch (e: UnknownHostException) {
                LOGGER.warn("UnknownHostException: ", e)
            }
            return false
        }
    }

    fun destroy() {
        if (crUpdater != null) {
            crUpdater!!.destroy()
        }
        if (stateUpdater != null) {
            stateUpdater!!.destroy()
        }
    }

    fun init() {
        val crHandler: AbstractUpdatable = object : AbstractUpdatable() {
            public override fun update(configStr: String?): Boolean {
                try {
                    try {
                        return configHandler!!.processConfig(configStr)
                    } catch (e: JsonUtilsException) {
                        LOGGER.warn(e, e)
                    }
                } catch (e: IOException) {
                    LOGGER.warn("error on config update", e)
                }
                return false
            }

            public override fun toString(): String {
                return "config listener"
            }

            public override fun noChange(): Boolean {
                try {
                    configHandler!!.processConfig(null)
                } catch (e: Exception) {
                    LOGGER.warn(e, e)
                }
                return false
            }

            public override fun complete() {
                if (!isLocalConfig && !isBootstrapped) {
                    isBootstrapped = true
                }
            }

            public override fun cancelUpdate() {
                configHandler!!.cancelProcessConfig()
            }
        }
        processConfig()
        crUpdater = PeriodicResourceUpdater(
            crHandler,
            TrafficMonitorResourceUrl(this, configUrl),
            databasesDirectory!!.resolve(configFile).toString(),
            configRefreshPeriod,
            true
        )
        crUpdater!!.init()
        stateUpdater = PeriodicResourceUpdater(
            stateHandler,
            TrafficMonitorResourceUrl(this, stateUrl),
            databasesDirectory!!.resolve(statusFile).toString(),
            statusRefreshPeriod,
            true
        )
        stateUpdater!!.init()
    }

    public override fun onApplicationEvent(event: ApplicationContextEvent?) {
        if (event is ContextClosedEvent) {
            crUpdater!!.destroy()
            stateUpdater!!.destroy()
        }
    }

    fun setMonitorProperties(monitorProperties: String?) {
        this.monitorProperties = monitorProperties
    }

    fun setMonitorHosts(monitorHosts: String?) {
        this.monitorHosts = monitorHosts
    }

    val hosts: Array<String>?
        get() {
            processConfig()
            return Companion.hosts
        }

    private fun processConfig() {
        val now: Long = System.currentTimeMillis()
        if (now < (lastHostAttempt + reloadPeriod)) {
            return
        }
        lastHostAttempt = now
        try {
            val trafficMonitorConfigFile: File
            if (monitorProperties!!.matches("^\\w+:.*")) {
                trafficMonitorConfigFile = File(URI(monitorProperties))
            } else {
                trafficMonitorConfigFile = File(monitorProperties)
            }
            val props: Properties = Properties()
            if (trafficMonitorConfigFile.exists()) {
                LOGGER.info("Loading properties from " + trafficMonitorConfigFile.getAbsolutePath())
                FileInputStream(trafficMonitorConfigFile).use({ configStream -> props.load(configStream) })
            } else {
                LOGGER.warn("Cannot load traffic monitor properties file " + trafficMonitorConfigFile.getAbsolutePath() + " file not found!")
            }
            var localConfig: Boolean =
                java.lang.Boolean.parseBoolean(props.getProperty("traffic_monitor.bootstrap.local", "false"))
            var localEnvString: String? = System.getenv("TRAFFIC_MONITOR_BOOTSTRAP_LOCAL")
            if (localEnvString != null) {
                localEnvString = localEnvString.toLowerCase()
            }
            if (("true" == localEnvString) || ("false" == localEnvString)) {
                localConfig = java.lang.Boolean.parseBoolean(localEnvString)
            }
            if (localConfig != isLocalConfig) {
                LOGGER.info("traffic_monitor.bootstrap.local changed to: " + localConfig)
                isLocalConfig = localConfig
            }
            if (localConfig || !isBootstrapped) {
                var hostList: String? = System.getenv("TRAFFIC_MONITOR_HOSTS")
                if (hostList != null && !hostList.isEmpty()) {
                    LOGGER.warn("hostlist initialized to '" + hostList + "' from env var 'TRAFFIC_MONITOR_HOSTS'")
                }
                if (hostList == null || hostList.isEmpty()) {
                    hostList = props.getProperty("traffic_monitor.bootstrap.hosts")
                }
                if (hostList == null || hostList.isEmpty()) {
                    if (!trafficMonitorConfigFile.exists()) {
                        LOGGER.fatal(trafficMonitorConfigFile.getAbsolutePath() + " does not exist and the environment variable 'TRAFFIC_MONITOR_HOSTS' was not found")
                    } else {
                        LOGGER.error("Cannot determine Traffic Monitor hosts from property 'traffic_monitor.bootstrap.hosts' in config file " + trafficMonitorConfigFile.getAbsolutePath())
                    }
                } else {
                    setHosts(if (hostList.contains(";")) hostList.split(";").toTypedArray() else arrayOf(hostList))
                }
            } else if (!isLocalConfig && isBootstrapped) {
                synchronized(monitorSync, {
                    if (!onlineMonitors.isEmpty()) {
                        setHosts(onlineMonitors.toTypedArray())
                    }
                })
            }
            val reloadPeriodStr: String? = props.getProperty("traffic_monitor.properties.reload.period")
            if (reloadPeriodStr != null) {
                val newReloadPeriod: Long = reloadPeriodStr.toInt().toLong()
                if (newReloadPeriod != reloadPeriod) {
                    reloadPeriod = newReloadPeriod
                    LOGGER.info("traffic_monitor.properties.reload.period changed to: " + reloadPeriod)
                }
            }
        } catch (e: Exception) {
            LOGGER.warn(e, e)
        }
        if (Companion.hosts == null) {
            Companion.hosts = monitorHosts!!.split(";").toTypedArray()
        }
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger(TrafficMonitorWatcher::class.java)
        var isBootstrapped: Boolean = false
            private set
        var isLocalConfig: Boolean = false
            private set
        private var onlineMonitors: List<String> = ArrayList()
        private var hosts: Array<String>?
        private val hostSync: Any = Any()
        private val monitorSync: Any = Any()
        fun setHosts(newHosts: Array<String>) {
            synchronized(hostSync, {
                if (hosts == null || hosts!!.size == 0) {
                    hosts = newHosts
                    LOGGER.info("traffic_monitor.bootstrap.hosts: " + Arrays.toString(hosts))
                } else if ((!Arrays.asList(*hosts).containsAll(Arrays.asList(*newHosts))
                            || !Arrays.asList(*newHosts).containsAll(Arrays.asList(*hosts)))
                ) {
                    hosts = newHosts
                    LOGGER.info("traffic_monitor.bootstrap.hosts changed to: " + Arrays.toString(hosts))
                }
            })
        }

        fun getOnlineMonitors(): List<String> {
            return onlineMonitors
        }

        fun setOnlineMonitors(onlineMonitors: List<String>) {
            synchronized(monitorSync, {
                if (isLocalConfig) {
                    return
                }
                Companion.onlineMonitors = onlineMonitors
                isBootstrapped = true
                setHosts(onlineMonitors.toTypedArray())
            })
        }
    }
}