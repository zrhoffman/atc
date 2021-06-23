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
package com.comcast.cdn.traffic_control.traffic_router.core.loc

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.beans.factory.annotation.Autowired
import com.comcast.cdn.traffic_control.traffic_router.core.util.DataExporter
import org.springframework.web.bind.annotation.GetMapping
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
import java.net.URLDecoder
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringTarget
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringFilter
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Dispersion
import java.util.SortedMap
import java.util.Collections
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.hash.DefaultHashable
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import java.util.HashSet
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.DeepCachingType
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import kotlin.Throws
import java.net.MalformedURLException
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import java.lang.StringBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import java.net.InetAddress
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.io.IOException
import java.security.GeneralSecurityException
import java.io.DataOutputStream
import java.util.SortedSet
import java.util.TreeSet
import java.io.UnsupportedEncodingException
import java.lang.StringBuffer
import com.comcast.cdn.traffic_control.traffic_router.core.util.StringProtector
import java.util.concurrent.atomic.AtomicInteger
import java.lang.IllegalArgumentException
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
import java.io.FileInputStream
import java.io.BufferedReader
import java.net.ServerSocket
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP
import java.io.DataInputStream
import org.xbill.DNS.WireParseException
import java.net.DatagramSocket
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import org.xbill.DNS.OPTRecord
import java.lang.Runnable
import java.util.concurrent.ExecutorService
import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServer
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.util.concurrent.TimeUnit
import java.lang.InterruptedException
import java.util.concurrent.ExecutionException
import org.xbill.DNS.Rcode
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneKey
import org.xbill.DNS.RRset
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRsetKey
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
import org.xbill.DNS.SOARecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import java.util.concurrent.ConcurrentMap
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRSIGCacheKey
import org.xbill.DNS.RRSIGRecord
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
import java.net.Inet6Address
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
import com.comcast.cdn.traffic_control.traffic_router.core.edge.TrafficRouterLocation
import org.xbill.DNS.NSECRecord
import org.xbill.DNS.CNAMERecord
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.NSRecord
import java.security.PrivateKey
import java.security.PublicKey
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRSetsBuilder
import java.util.OptionalLong
import java.util.function.ToLongFunction
import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServerMain
import kotlin.jvm.JvmStatic
import org.springframework.context.support.ClassPathXmlApplicationContext
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSigner
import java.util.stream.StreamSupport
import org.xbill.DNS.DNSSEC
import org.xbill.DNS.DNSSEC.DNSSECException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import java.util.function.BiFunction
import java.util.function.ToIntFunction
import com.comcast.cdn.traffic_control.traffic_router.core.util.ProtectedFetcher
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import java.util.function.BinaryOperator
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
import java.util.NoSuchElementException
import org.springframework.web.filter.OncePerRequestFilter
import com.comcast.cdn.traffic_control.traffic_router.core.http.HTTPAccessRecord
import com.comcast.cdn.traffic_control.traffic_router.core.http.RouterFilter
import com.comcast.cdn.traffic_control.traffic_router.core.http.HTTPAccessEventBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.http.HttpAccessRequestHeaders
import javax.net.ssl.TrustManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.Fetcher.DefaultTrustManager
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.X509TrustManager
import javax.net.ssl.HostnameVerifier
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
import java.io.FileReader
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractUpdatable
import org.asynchttpclient.AsyncHttpClient
import com.comcast.cdn.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
import org.asynchttpclient.DefaultAsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClientConfig
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
import com.comcast.cdn.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesResponse
import org.springframework.core.env.Environment
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import org.springframework.context.event.ContextClosedEvent
import java.util.Enumeration
import org.powermock.core.classloader.annotations.PrepareForTest
import org.junit.runner.RunWith
import org.powermock.modules.junit4.PowerMockRunner
import org.junit.Before
import com.comcast.cdn.traffic_control.traffic_router.shared.ZoneTestRecords
import org.powermock.api.mockito.PowerMockito
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest.FakeAbstractProtocol
import java.lang.System
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest
import com.comcast.cdn.traffic_control.traffic_router.core.util.IntegrationTest
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManagerTest
import org.junit.BeforeClass
import java.nio.file.Paths
import com.comcast.cdn.traffic_control.traffic_router.core.TestBase
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImplTest.IsRRsetTypeA
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImplTest.IsRRsetTypeNSEC
import com.comcast.cdn.traffic_control.traffic_router.core.loc.GeoTest
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeTest
import com.comcast.cdn.traffic_control.traffic_router.core.loc.MaxmindGeoIP2Test
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AbstractServiceUpdaterTest.Updater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseServiceTest
import org.powermock.core.classloader.annotations.PowerMockIgnore
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcherTest
import java.lang.Void
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatelessTrafficRouterTest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import com.comcast.cdn.traffic_control.traffic_router.core.util.ExternalTest
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.catalina.LifecycleException
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.util.EntityUtils
import org.junit.FixMethodOrder
import org.junit.runners.MethodSorters
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import com.comcast.cdn.traffic_control.traffic_router.core.external.RouterTest.ClientSslSocketFactory
import com.comcast.cdn.traffic_control.traffic_router.core.external.RouterTest.TestHostnameVerifier
import org.xbill.DNS.SimpleResolver
import javax.net.ssl.SSLHandshakeException
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpHead
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLParameters
import org.hamcrest.number.IsCloseTo
import java.net.InetSocketAddress
import com.sun.net.httpserver.HttpExchange
import org.junit.runners.Suite
import org.junit.runners.Suite.SuiteClasses
import com.comcast.cdn.traffic_control.traffic_router.core.external.SteeringTest
import com.comcast.cdn.traffic_control.traffic_router.core.external.ConsistentHashTest
import com.comcast.cdn.traffic_control.traffic_router.core.external.DeliveryServicesTest
import com.comcast.cdn.traffic_control.traffic_router.core.external.LocationsTest
import com.comcast.cdn.traffic_control.traffic_router.core.external.RouterTest
import com.comcast.cdn.traffic_control.traffic_router.core.external.StatsTest
import com.comcast.cdn.traffic_control.traffic_router.core.external.ZonesTest
import com.comcast.cdn.traffic_control.traffic_router.core.CatalinaTrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Location
import com.comcast.cdn.traffic_control.traffic_router.core.external.HttpDataServer
import com.comcast.cdn.traffic_control.traffic_router.core.external.ExternalTestSuite
import org.apache.log4j.ConsoleAppender
import org.apache.log4j.PatternLayout
import org.junit.AfterClass
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.FileVisitResult
import org.hamcrest.number.OrderingComparison
import javax.management.MBeanServer
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.support.FileSystemXmlApplicationContext
import org.apache.catalina.startup.Catalina
import org.apache.catalina.core.StandardService
import org.apache.catalina.core.StandardHost
import org.apache.catalina.core.StandardContext
import org.apache.log4j.Logger
import java.io.File
import java.net.UnknownHostException
import java.util.ArrayList

open class NetworkNode @JvmOverloads constructor(
    str: String?,
    private val loc: String? = null,
    geolocation: Geolocation? = null
) : Comparable<NetworkNode?> {
    private val cidrAddress: CidrAddress?
    private var location: Location? = null
    private val geolocation: Geolocation? = null
    var children: MutableMap<NetworkNode?, NetworkNode?>? = null
    private var deepCacheNames: MutableSet<String?>? = null
    @Throws(NetworkNodeException::class)
    open fun getNetwork(ip: String?): NetworkNode? {
        return getNetwork(NetworkNode(ip))
    }

    fun getNetwork(ipnn: NetworkNode?): NetworkNode? {
        if (this.compareTo(ipnn) != 0) {
            return null
        }
        if (children == null) {
            return this
        }
        val c: NetworkNode? = children.get(ipnn)
        if (c == null) {
            return this
        }
        return c.getNetwork(ipnn)
    }

    fun add(nn: NetworkNode?): Boolean? {
        synchronized(this, {
            if (children == null) {
                children = TreeMap()
            }
            return add(children, nn)
        })
    }

    protected fun add(children: MutableMap<NetworkNode?, NetworkNode?>?, networkNode: NetworkNode?): Boolean? {
        if (compareTo(networkNode) != 0) {
            return false
        }
        for (child: NetworkNode? in children.values) {
            if ((child.cidrAddress == networkNode.cidrAddress)) {
                return false
            }
        }
        val movedChildren: MutableList<NetworkNode?>? = ArrayList()
        for (child: NetworkNode? in children.values) {
            if (networkNode.cidrAddress.includesAddress(child.cidrAddress)) {
                movedChildren.add(child)
                networkNode.add(child)
            }
        }
        for (movedChild: NetworkNode? in movedChildren) {
            children.remove(movedChild)
        }
        for (child: NetworkNode? in children.values) {
            if (child.cidrAddress.includesAddress(networkNode.cidrAddress)) {
                return child.add(networkNode)
            }
        }
        children.put(networkNode, networkNode)
        return true
    }

    fun getLoc(): String? {
        return loc
    }

    fun getGeolocation(): Geolocation? {
        return geolocation
    }

    fun getLocation(): Location? {
        return location
    }

    fun setLocation(location: Location?) {
        this.location = location
    }

    fun getDeepCacheNames(): MutableSet<String?>? {
        return deepCacheNames
    }

    fun setDeepCacheNames(deepCacheNames: MutableSet<String?>?) {
        this.deepCacheNames = deepCacheNames
    }

    fun size(): Int {
        if (children == null) {
            return 1
        }
        var size: Int = 1
        for (child: NetworkNode? in children.keys) {
            size += child.size()
        }
        return size
    }

    @JvmOverloads
    fun clearLocations(clearCachesOnly: Boolean = false) {
        synchronized(this, {
            if (clearCachesOnly && (location != null) && location is CacheLocation) {
                (location as CacheLocation?).clearCaches()
            } else {
                location = null
            }
            if (this is SuperNode) {
                val superNode: SuperNode? = this as SuperNode?
                if (superNode.children6 != null) {
                    for (child: NetworkNode? in superNode.children6.keys) {
                        child.clearLocations(clearCachesOnly)
                    }
                }
            }
            if (children != null) {
                for (child: NetworkNode? in children.keys) {
                    child.clearLocations(clearCachesOnly)
                }
            }
        })
    }

    class SuperNode constructor() : NetworkNode(DEFAULT_SUB_STR) {
        private var children6: MutableMap<NetworkNode?, NetworkNode?>? = null
        fun add6(nn: NetworkNode?): Boolean? {
            if (children6 == null) {
                children6 = TreeMap()
            }
            return add(children6, nn)
        }

        @Throws(NetworkNodeException::class)
        public override fun getNetwork(ip: String?): NetworkNode? {
            val nn: NetworkNode? = NetworkNode(ip)
            if (nn.cidrAddress.isIpV6()) {
                return getNetwork6(nn)
            }
            return getNetwork(nn)
        }

        fun getNetwork6(networkNode: NetworkNode?): NetworkNode? {
            if (children6 == null) {
                return this
            }
            val c: NetworkNode? = children6.get(networkNode)
            if (c == null) {
                return this
            }
            return c.getNetwork(networkNode)
        }
    }

    public override fun compareTo(other: NetworkNode?): Int {
        return cidrAddress.compareTo(other.cidrAddress)
    }

    public override fun toString(): String {
        var str: String? = ""
        try {
            str = InetAddress.getByAddress(cidrAddress.getHostBytes()).toString().replace("/", "")
        } catch (e: UnknownHostException) {
            LOGGER.warn(e, e)
        }
        return "[" + str + "/" + cidrAddress.getNetmaskLength() + "] - location:" + getLoc()
    }

    companion object {
        private val LOGGER: Logger? = Logger.getLogger(NetworkNode::class.java)
        private val DEFAULT_SUB_STR: String? = "0.0.0.0/0"
        private var instance: NetworkNode? = null
        private var deepInstance: NetworkNode? = null
        fun getInstance(): NetworkNode? {
            if (instance != null) {
                return instance
            }
            try {
                instance = NetworkNode(DEFAULT_SUB_STR)
            } catch (e: NetworkNodeException) {
                LOGGER.warn(e)
            }
            return instance
        }

        fun getDeepInstance(): NetworkNode? {
            if (deepInstance != null) {
                return deepInstance
            }
            try {
                deepInstance = NetworkNode(DEFAULT_SUB_STR)
            } catch (e: NetworkNodeException) {
                LOGGER.warn(e)
            }
            return deepInstance
        }

        @JvmOverloads
        @Throws(IOException::class)
        fun generateTree(f: File?, verifyOnly: Boolean, useDeep: Boolean = false): NetworkNode? {
            val mapper: ObjectMapper? = ObjectMapper()
            return generateTree(mapper.readTree(f), verifyOnly, useDeep)
        }

        @JvmOverloads
        fun generateTree(json: JsonNode?, verifyOnly: Boolean, useDeep: Boolean = false): NetworkNode? {
            try {
                val czKey: String? = if (useDeep) "deepCoverageZones" else "coverageZones"
                val coverageZones: JsonNode? = JsonUtils.getJsonNode(json, czKey)
                val root: SuperNode? = SuperNode()
                val czIter: MutableIterator<String?>? = coverageZones.fieldNames()
                while (czIter.hasNext()) {
                    val loc: String? = czIter.next()
                    val locData: JsonNode? = JsonUtils.getJsonNode(coverageZones, loc)
                    val coordinates: JsonNode? = locData.get("coordinates")
                    var geolocation: Geolocation? = null
                    if ((coordinates != null) && coordinates.has("latitude") && coordinates.has("longitude")) {
                        val latitude: Double = coordinates.get("latitude").asDouble()
                        val longitude: Double = coordinates.get("longitude").asDouble()
                        geolocation = Geolocation(latitude, longitude)
                    }
                    if (!addNetworkNodesToRoot(root, loc, locData, geolocation, useDeep)) {
                        return null
                    }
                }
                if (!verifyOnly) {
                    if (useDeep) {
                        deepInstance = root
                    } else {
                        instance = root
                    }
                }
                return root
            } catch (ex: JsonUtilsException) {
                LOGGER.warn(ex, ex)
            } catch (ex: NetworkNodeException) {
                LOGGER.fatal(ex, ex)
            }
            return null
        }

        private fun addNetworkNodesToRoot(
            root: SuperNode?, loc: String?, locData: JsonNode?,
            geolocation: Geolocation?, useDeep: Boolean
        ): Boolean {
            val deepLoc: CacheLocation? = CacheLocation(
                "deep." + loc,
                if (geolocation != null) geolocation else Geolocation(0.0, 0.0)
            ) // TODO JvD
            val cacheNames: MutableSet<String?>? = parseDeepCacheNames(locData)
            for (key: String? in arrayOf<String?>("network6", "network")) {
                try {
                    for (network: JsonNode? in JsonUtils.getJsonNode(locData, key)) {
                        val ip: String? = network.asText()
                        try {
                            val nn: NetworkNode? = NetworkNode(ip, loc, geolocation)
                            if (useDeep) {
                                // For a deep NetworkNode, we set the CacheLocation here without any Caches.
                                // The deep Caches will be lazily loaded in getCoverageZoneCacheLocation() where we have
                                // access to the latest CacheRegister, similar to how normal NetworkNodes are lazily loaded
                                // with a CacheLocation.
                                nn.setDeepCacheNames(cacheNames)
                                nn.setLocation(deepLoc)
                            }
                            if (("network6" == key)) {
                                root.add6(nn)
                            } else {
                                root.add(nn)
                            }
                        } catch (ex: NetworkNodeException) {
                            LOGGER.error(ex, ex)
                            return false
                        }
                    }
                } catch (ex: JsonUtilsException) {
                    LOGGER.warn("An exception was caught while accessing the " + key + " key of " + loc + " in the incoming coverage zone file: " + ex.message)
                }
            }
            return true
        }

        private fun parseDeepCacheNames(locationData: JsonNode?): MutableSet<String?>? {
            val cacheNames: MutableSet<String?>? = HashSet()
            val cacheArray: JsonNode?
            try {
                cacheArray = JsonUtils.getJsonNode(locationData, "caches")
            } catch (ex: JsonUtilsException) {
                return cacheNames
            }
            for (cache: JsonNode? in cacheArray) {
                val cacheName: String? = cache.asText()
                if (!cacheName.isEmpty()) {
                    cacheNames.add(cacheName)
                }
            }
            return cacheNames
        }
    }

    init {
        this.geolocation = geolocation
        cidrAddress = CidrAddress.Companion.fromString(str)
    }
}