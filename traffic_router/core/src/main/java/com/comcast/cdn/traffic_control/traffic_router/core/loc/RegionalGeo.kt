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
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache
import com.comcast.cdn.traffic_control.traffic_router.core.external.HttpDataServer
import com.comcast.cdn.traffic_control.traffic_router.core.external.ExternalTestSuite
import com.comcast.cdn.traffic_control.traffic_router.core.request.Request
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
import java.lang.Exception
import java.net.URL
import java.util.ArrayList
import java.util.regex.Pattern

class RegionalGeo private constructor() {
    private var fallback: Boolean = false
    private val regionalGeoDsvcs: MutableMap<String?, RegionalGeoDsvc?>? = HashMap()
    fun setFallback(fallback: Boolean) {
        this.fallback = fallback
    }

    fun isFallback(): Boolean {
        return fallback
    }

    private fun matchRule(dsvcId: String?, url: String?): RegionalGeoRule? {
        val regionalGeoDsvc: RegionalGeoDsvc? = regionalGeoDsvcs.get(dsvcId)
        if (regionalGeoDsvc == null) {
            LOGGER.debug("RegionalGeo: dsvc not found: " + dsvcId)
            return null
        }
        val rule: RegionalGeoRule? = regionalGeoDsvc.matchRule(url)
        if (rule == null) {
            LOGGER.debug(
                ("RegionalGeo: no rule match for dsvc "
                        + dsvcId + " with url " + url)
            )
            return null
        }
        return rule
    }

    private fun addRule(
        dsvcId: String?,
        urlRegex: String?,
        postalsType: PostalsType?,
        postals: MutableSet<String?>?,
        networkRoot: NetworkNode?,
        alternateUrl: String?,
        isSteeringDS: Boolean,
        coordinateRanges: MutableList<RegionalGeoCoordinateRange?>?
    ): Boolean {

        // Loop check for alternateUrl with fqdn against the regex before adding
        val urlRegexPattern: Pattern?
        try {
            LOGGER.info("RegionalGeo: compile regex for url " + urlRegex)
            urlRegexPattern = Pattern.compile(urlRegex, Pattern.CASE_INSENSITIVE)
        } catch (e: Exception) {
            LOGGER.error("RegionalGeo ERR: Pattern.compile exception", e)
            return false
        }
        if (((alternateUrl.toLowerCase().startsWith(HTTP_SCHEME) || alternateUrl.toLowerCase().startsWith(HTTPS_SCHEME))
                    && urlRegexPattern.matcher(alternateUrl).matches())
        ) {
            LOGGER.error(
                ("RegionalGeo ERR: possible LOOP detected, alternate fqdn url " + alternateUrl
                        + " matches regex " + urlRegex + " in dsvc " + dsvcId)
            )
            return false
        }
        if (isSteeringDS && !(alternateUrl.toLowerCase().startsWith(HTTP_SCHEME) || alternateUrl.toLowerCase()
                .startsWith(
                    HTTPS_SCHEME
                ))
        ) {
            LOGGER.error(
                ("RegionalGeo ERR: Alternate URL for Steering delivery service: "
                        + dsvcId + " must start with " + HTTP_SCHEME + " or " + HTTPS_SCHEME)
            )
            return false
        }
        var regionalGeoDsvc: RegionalGeoDsvc? = regionalGeoDsvcs.get(dsvcId)
        if (regionalGeoDsvc == null) {
            regionalGeoDsvc = RegionalGeoDsvc(dsvcId)
            regionalGeoDsvcs.put(dsvcId, regionalGeoDsvc)
        }
        val urlRule: RegionalGeoRule? = RegionalGeoRule(
            regionalGeoDsvc,
            urlRegex, urlRegexPattern,
            postalsType, postals,
            networkRoot, alternateUrl, coordinateRanges
        )
        LOGGER.info("RegionalGeo: adding " + urlRule)
        regionalGeoDsvc.addRule(urlRule)
        return true
    }

    companion object {
        private val LOGGER: Logger? = Logger.getLogger(RegionalGeo::class.java)
        val HTTP_SCHEME: String? = "http://"
        val HTTPS_SCHEME: String? = "https://"
        private var currentConfig: RegionalGeo? = RegionalGeo()

        /// static methods
        @Throws(NetworkNodeException::class)
        private fun parseWhiteListJson(json: JsonNode?): NetworkNode? {
            val root: SuperNode? = SuperNode()
            for (subnetNode: JsonNode? in json) {
                val subnet: String? = subnetNode.asText()
                val node: NetworkNode? = NetworkNode(subnet, RegionalGeoRule.Companion.WHITE_LIST_NODE_LOCATION)
                if (subnet.indexOf(':') == -1) { // ipv4 or ipv6
                    root.add(node)
                } else {
                    root.add6(node)
                }
            }
            return root
        }

        private fun checkCoordinateRangeValidity(cr: RegionalGeoCoordinateRange?): Boolean {
            if (((cr.getMinLat() < -90.0 || cr.getMinLat() > 90.0) ||
                        (cr.getMaxLat() < -90.0 || cr.getMaxLat() > 90.0) ||
                        (cr.getMinLon() < -180.0 || cr.getMinLon() > 180.0) ||
                        (cr.getMaxLon() < -180.0 || cr.getMaxLon() > 180.0))
            ) {
                LOGGER.error("The supplied coordinate range is invalid. Latitude must be between -90.0 and +90.0, Longitude must be between -180.0 and +180.0.")
                return false
            }
            return true
        }

        private fun parseLocationJsonCoordinateRange(locationJson: JsonNode?): MutableList<RegionalGeoCoordinateRange?>? {
            val coordinateRange: MutableList<RegionalGeoCoordinateRange?>? = ArrayList()
            val coordinateRangeJson: JsonNode? = locationJson.get("coordinateRange")
            if (coordinateRangeJson == null) {
                return null
            }
            val mapper: ObjectMapper? = ObjectMapper()
            var cr: RegionalGeoCoordinateRange? = RegionalGeoCoordinateRange()
            for (cRange: JsonNode? in coordinateRangeJson) {
                cr = mapper.convertValue(cRange, RegionalGeoCoordinateRange::class.java)
                if (checkCoordinateRangeValidity(cr)) {
                    coordinateRange.add(cr)
                }
            }
            return coordinateRange
        }

        private fun parseLocationJson(
            locationJson: JsonNode?,
            postals: MutableSet<String?>?
        ): PostalsType? {
            var postalsType: PostalsType? = PostalsType.UNDEFINED
            var postalsJson: JsonNode? = locationJson.get("includePostalCode")
            if (postalsJson != null) {
                postalsType = PostalsType.INCLUDE
            } else {
                postalsJson = locationJson.get("excludePostalCode")
                if (postalsJson == null) {
                    LOGGER.error("RegionalGeo ERR: no include/exclude in geolocation")
                    return PostalsType.UNDEFINED
                }
                postalsType = PostalsType.EXCLUDE
            }
            for (postal: JsonNode? in postalsJson) {
                postals.add(postal.asText())
            }
            return postalsType
        }

        private fun parseConfigJson(json: JsonNode?): RegionalGeo? {
            val regionalGeo: RegionalGeo? = RegionalGeo()
            regionalGeo.setFallback(true)
            try {
                val dsvcsJson: JsonNode? = JsonUtils.getJsonNode(json, "deliveryServices")
                LOGGER.info("RegionalGeo: parse json with rule count " + dsvcsJson.size())
                for (ruleJson: JsonNode? in dsvcsJson) {
                    val dsvcId: String? = JsonUtils.getString(ruleJson, "deliveryServiceId")
                    if (dsvcId.trim({ it <= ' ' }).isEmpty()) {
                        LOGGER.error("RegionalGeo ERR: deliveryServiceId empty")
                        return null
                    }
                    var isSteeringDS: Boolean? = false
                    try {
                        isSteeringDS = JsonUtils.getBoolean(ruleJson, "isSteeringDS")
                    } catch (e: JsonUtilsException) {
                        //It's not in the config so we can just keep it set as false.
                        LOGGER.debug("RegionalGeo ERR: isSteeringDS empty")
                    }
                    val urlRegex: String? = JsonUtils.getString(ruleJson, "urlRegex")
                    if (urlRegex.trim({ it <= ' ' }).isEmpty()) {
                        LOGGER.error("RegionalGeo ERR: urlRegex empty")
                        return null
                    }
                    val redirectUrl: String? = JsonUtils.getString(ruleJson, "redirectUrl")
                    if (redirectUrl.trim({ it <= ' ' }).isEmpty()) {
                        LOGGER.error("RegionalGeo ERR: redirectUrl empty")
                        return null
                    }

                    // FSAs (postal codes)
                    val locationJson: JsonNode? = JsonUtils.getJsonNode(ruleJson, "geoLocation")
                    val postals: MutableSet<String?>? = HashSet()
                    val postalsType: PostalsType? = parseLocationJson(locationJson, postals)
                    if (postalsType == PostalsType.UNDEFINED) {
                        LOGGER.error("RegionalGeo ERR: geoLocation empty")
                        return null
                    }
                    // coordinate range
                    val coordinateRanges: MutableList<RegionalGeoCoordinateRange?>? =
                        parseLocationJsonCoordinateRange(locationJson)

                    // white list
                    var whiteListRoot: NetworkNode? = null
                    val whiteListJson: JsonNode? = ruleJson.get("ipWhiteList")
                    if (whiteListJson != null) {
                        whiteListRoot = parseWhiteListJson(whiteListJson)
                    }


                    // add the rule
                    if (!regionalGeo.addRule(
                            dsvcId,
                            urlRegex,
                            postalsType,
                            postals,
                            whiteListRoot,
                            redirectUrl,
                            isSteeringDS,
                            coordinateRanges
                        )
                    ) {
                        LOGGER.error("RegionalGeo ERR: add rule failed on parsing json file")
                        return null
                    }
                }
                regionalGeo.setFallback(false)
                return regionalGeo
            } catch (e: Exception) {
                LOGGER.error("RegionalGeo ERR: parse json file with exception", e)
            }
            return null
        }

        fun parseConfigFile(f: File?, verifyOnly: Boolean): Boolean {
            val mapper: ObjectMapper? = ObjectMapper()
            var json: JsonNode? = null
            try {
                json = mapper.readTree(f)
            } catch (e: Exception) {
                LOGGER.error("RegionalGeo ERR: json file exception " + f, e)
                currentConfig.setFallback(true)
                return false
            }
            val regionalGeo: RegionalGeo? = parseConfigJson(json)
            if (regionalGeo == null) {
                currentConfig.setFallback(true)
                return false
            }
            if (!verifyOnly) {
                currentConfig = regionalGeo // point to the new parsed object
            }
            currentConfig.setFallback(false)
            LOGGER.debug("RegionalGeo: create instance from new json")
            return true
        }

        fun enforce(
            dsvcId: String?, url: String?,
            ip: String?, postalCode: String?, lat: Double, lon: Double
        ): RegionalGeoResult? {
            val result: RegionalGeoResult? = RegionalGeoResult()
            var allowed: Boolean = false
            var rule: RegionalGeoRule? = null
            result.setPostal(postalCode)
            result.setUsingFallbackConfig(currentConfig.isFallback())
            result.setAllowedByWhiteList(false)
            rule = currentConfig.matchRule(dsvcId, url)
            if (rule == null) {
                result.setHttpResponseCode(RegionalGeoResult.Companion.REGIONAL_GEO_DENIED_HTTP_CODE)
                result.setType(RegionalGeoResultType.DENIED)
                LOGGER.debug(
                    ("RegionalGeo: denied for dsvc " + dsvcId
                            + ", url " + url + ", postal " + postalCode)
                )
                return result
            }

            // first match whitelist, then FSA (postal)
            if (rule.isIpInWhiteList(ip)) {
                LOGGER.debug("RegionalGeo: allowing ip in whitelist")
                allowed = true
                result.setAllowedByWhiteList(true)
            } else {
                if (postalCode == null || postalCode.isEmpty()) {
                    LOGGER.warn("RegionalGeo: alternate a request with null or empty postal")
                    allowed = rule.isAllowedCoordinates(lat, lon)
                } else {
                    allowed = rule.isAllowedPostal(postalCode)
                }
            }
            val alternateUrl: String? = rule.getAlternateUrl()
            result.setRuleType(rule.getPostalsType())
            if (allowed) {
                result.setUrl(url)
                result.setType(RegionalGeoResultType.ALLOWED)
            } else {
                // For a disallowed client, if alternateUrl starts with "http://" or "https://"
                // just redirect the client to this url without any cache selection;
                // if alternateUrl only has path and file name like "/path/abc.html",
                // then cache selection process will be needed, and hostname will be
                // added to make it like "http://cache01.example.com/path/abc.html" later.
                if (alternateUrl.toLowerCase().startsWith(HTTP_SCHEME) || alternateUrl.toLowerCase()
                        .startsWith(HTTPS_SCHEME)
                ) {
                    result.setUrl(alternateUrl)
                    result.setType(RegionalGeoResultType.ALTERNATE_WITHOUT_CACHE)
                } else {
                    val redirectUrl: String?
                    if (alternateUrl.startsWith("/")) { // add a '/' prefix if necessary for url path
                        redirectUrl = alternateUrl
                    } else {
                        redirectUrl = "/" + alternateUrl
                    }
                    LOGGER.debug("RegionalGeo: alternate with cache url " + redirectUrl)
                    result.setUrl(redirectUrl)
                    result.setType(RegionalGeoResultType.ALTERNATE_WITH_CACHE)
                }
            }
            LOGGER.debug("RegionalGeo: result " + result + " for dsvc " + dsvcId + ", url " + url + ", ip " + ip)
            return result
        }

        @JvmOverloads
        @Throws(MalformedURLException::class)
        fun enforce(
            trafficRouter: TrafficRouter?, request: Request?,
            deliveryService: DeliveryService?, cache: Cache?,
            routeResult: HTTPRouteResult?, track: StatTracker.Track?, isSteering: Boolean = false
        ) {
            LOGGER.debug("RegionalGeo: enforcing")
            var clientGeolocation: Geolocation? = null
            try {
                clientGeolocation = trafficRouter.getClientGeolocation(request.getClientIP(), track, deliveryService)
            } catch (e: GeolocationException) {
                LOGGER.warn("RegionalGeo: failed looking up Client GeoLocation: " + e.message)
            }
            var postalCode: String? = null
            var lat: Double = 0.0
            var lon: Double = 0.0
            if (clientGeolocation != null) {
                postalCode = clientGeolocation.getPostalCode()

                // Get the first 3 chars in the postal code. These 3 chars are called FSA in Canadian postal codes.
                if (postalCode != null && postalCode.length > 3) {
                    postalCode = postalCode.substring(0, 3)
                } else {
                    lat = clientGeolocation.getLatitude()
                    lon = clientGeolocation.getLongitude()
                }
            }
            val httpRequest: HTTPRequest? = HTTPRequest::class.java.cast(request)
            val result: RegionalGeoResult? = enforce(
                deliveryService.getId(), httpRequest.getRequestedUrl(),
                httpRequest.getClientIP(), postalCode, lat, lon
            )
            if (cache == null && result.getType() == RegionalGeoResultType.ALTERNATE_WITH_CACHE) {
                LOGGER.debug("RegionalGeo: denied for dsvc " + deliveryService.getId() + ", url " + httpRequest.getRequestedUrl() + ", postal " + postalCode + ". Relative re-direct URLs not allowed for Multi Route Delivery Services.")
                result.setHttpResponseCode(RegionalGeoResult.Companion.REGIONAL_GEO_DENIED_HTTP_CODE)
                result.setType(RegionalGeoResultType.DENIED)
            }
            if (cache == null && result.getType() == RegionalGeoResultType.ALLOWED) {
                LOGGER.debug("RegionalGeo: Client is allowed to access steering service, returning null re-direct URL")
                result.setUrl(null)
                updateTrack(track, result)
                return
            }
            updateTrack(track, result)
            if (result.getType() == RegionalGeoResultType.DENIED) {
                routeResult.setResponseCode(result.getHttpResponseCode())
            } else {
                val redirectURIString: String? = createRedirectURIString(httpRequest, deliveryService, cache, result)
                if (!("Denied" == redirectURIString)) {
                    routeResult.addUrl(URL(redirectURIString))
                } else {
                    LOGGER.warn("RegionalGeo: this needs a better error message, createRedirectURIString returned denied")
                }
            }
        }

        private fun updateTrack(track: StatTracker.Track?, regionalGeoResult: RegionalGeoResult?) {
            track.setRegionalGeoResult(regionalGeoResult)
            val resultType: RegionalGeoResultType? = regionalGeoResult.getType()
            if (resultType == RegionalGeoResultType.DENIED) {
                track.setResult(ResultType.RGDENY)
                track.setResultDetails(ResultDetails.REGIONAL_GEO_NO_RULE)
                return
            }
            if (resultType == RegionalGeoResultType.ALTERNATE_WITH_CACHE) {
                track.setResult(ResultType.RGALT)
                track.setResultDetails(ResultDetails.REGIONAL_GEO_ALTERNATE_WITH_CACHE)
                return
            }
            if (resultType == RegionalGeoResultType.ALTERNATE_WITHOUT_CACHE) {
                track.setResult(ResultType.RGALT)
                track.setResultDetails(ResultDetails.REGIONAL_GEO_ALTERNATE_WITHOUT_CACHE)
                return
            }

            // else ALLOWED, result & resultDetail shall be normal case, do not modify
        }

        private fun createRedirectURIString(
            request: HTTPRequest?, deliveryService: DeliveryService?,
            cache: Cache?, regionalGeoResult: RegionalGeoResult?
        ): String? {
            if (regionalGeoResult.getType() == RegionalGeoResultType.ALLOWED) {
                return deliveryService.createURIString(request, cache)
            }
            if (regionalGeoResult.getType() == RegionalGeoResultType.ALTERNATE_WITH_CACHE) {
                return deliveryService.createURIString(request, regionalGeoResult.getUrl(), cache)
            }
            if (regionalGeoResult.getType() == RegionalGeoResultType.ALTERNATE_WITHOUT_CACHE) {
                return regionalGeoResult.getUrl()
            }
            return "Denied" // DENIED
        }
    }
}