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
package com.comcast.cdn.traffic_control.traffic_router.core.ds

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
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.databind.JsonNode
import org.springframework.context.support.FileSystemXmlApplicationContext
import org.apache.catalina.startup.Catalina
import org.apache.catalina.core.StandardService
import org.apache.catalina.core.StandardHost
import org.apache.catalina.core.StandardContext
import org.apache.log4j.Logger
import java.io.ByteArrayOutputStream
import java.lang.Exception
import java.net.URL
import java.net.UnknownHostException
import java.util.ArrayList
import java.util.function.Consumer
import java.util.regex.Pattern

class DeliveryService(private val id: String?, @field:JsonIgnore private val props: JsonNode?) {
    @JsonIgnore
    private val ttls: JsonNode?
    private val coverageZoneOnly: Boolean

    @JsonIgnore
    private val geoEnabled: JsonNode?
    private val geoRedirectUrl: String?

    //store the url file path info
    private var geoRedirectFile: String?

    //check if the geoRedirectUrl belongs to this DeliveryService, avoid calculating this for multiple times
    //"INVALID_URL" for init status, "DS_URL" means that the request url belongs to this DeliveryService, "NOT_DS_URL" means that the request url doesn't belong to this DeliveryService
    private var geoRedirectUrlType: String?

    @JsonIgnore
    private val staticDnsEntries: JsonNode?

    @JsonIgnore
    private val domain: String?

    @JsonIgnore
    private val tld: String?

    @JsonIgnore // Matches the beginning of a HOST_REGEXP pattern with or without confighandler.regex.superhack.enabled.
    // ^\(\.\*\\\.\|\^\)|^\.\*\\\.|\\\.\.\*
    private val wildcardPattern = Pattern.compile("^\\(\\.\\*\\\\\\.\\|\\^\\)|^\\.\\*\\\\\\.|\\\\\\.\\.\\*")

    @JsonIgnore
    private val bypassDestination: JsonNode?

    @JsonIgnore
    private val soa: JsonNode?
    private var isDns = false
    private val routingName: String?
    private val topology: String? = null
    private val requiredCapabilities: MutableSet<String?>?
    private val shouldAppendQueryString: Boolean
    private val missLocation: Geolocation? = null
    private val dispersion: Dispersion?
    private val ip6RoutingEnabled: Boolean
    private val responseHeaders: MutableMap<String?, String?>? = HashMap()
    private val requestHeaders: MutableSet<String?>? = HashSet()
    private val regionalGeoEnabled: Boolean
    private val geolocationProvider: String?
    private val anonymousIpEnabled: Boolean
    private val sslEnabled: Boolean
    private var hasX509Cert = false
    private val acceptHttp: Boolean
    private val acceptHttps: Boolean
    private val redirectToHttps: Boolean
    private val deepCache: DeepCachingType? = null
    private var consistentHashRegex: String?
    private val consistentHashQueryParams: MutableSet<String?>?
    private var ecsEnabled: Boolean

    enum class DeepCachingType {
        NEVER, ALWAYS
    }

    private fun getDomainFromJson(domains: JsonNode?): String? {
        return domains?.get(0)?.asText()
    }

    fun getConsistentHashQueryParams(): MutableSet<String?>? {
        return consistentHashQueryParams
    }

    fun getId(): String? {
        return id
    }

    @JsonIgnore
    fun getTtls(): JsonNode? {
        return ttls
    }

    override fun toString(): String {
        return "DeliveryService [id=$id]"
    }

    fun getMissLocation(): Geolocation? {
        return missLocation
    }

    fun supportLocation(clientLocation: Geolocation?): Geolocation? {
        if (clientLocation == null) {
            return missLocation
        }
        return if (isLocationBlocked(clientLocation)) {
            null
        } else clientLocation
    }

    private fun isLocationBlocked(clientLocation: Geolocation?): Boolean {
        if (geoEnabled == null || geoEnabled.size() == 0) {
            return false
        }
        val locData = clientLocation.getProperties()
        for (constraint in geoEnabled) {
            var match = true
            try {
                val keyIter = constraint.fieldNames()
                while (keyIter.hasNext()) {
                    val t = keyIter.next()
                    val v = JsonUtils.getString(constraint, t)
                    val data = locData[t]
                    if (!v.equals(data, ignoreCase = true)) {
                        match = false
                        break
                    }
                }
                if (match) {
                    return false
                }
            } catch (ex: JsonUtilsException) {
                LOGGER.warn(ex, ex)
            }
        }
        return true
    }

    fun isCoverageZoneOnly(): Boolean {
        return coverageZoneOnly
    }

    @Throws(MalformedURLException::class)
    fun getFailureHttpResponse(request: HTTPRequest?, track: StatTracker.Track?): URL? {
        if (bypassDestination == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        track.setResult(ResultType.DS_REDIRECT)
        val httpJo = bypassDestination["HTTP"]
        if (httpJo == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        val fqdn = httpJo["fqdn"]
        if (fqdn == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        var port = if (request.isSecure()) 443 else 80
        if (httpJo.has("port")) {
            port = httpJo["port"].asInt()
        }
        return URL(createURIString(request, fqdn.asText(), port, null))
    }

    private fun useSecure(request: HTTPRequest?): Boolean {
        return if (request.isSecure()) {
            acceptHttps && isSslReady()
        } else redirectToHttps && acceptHttps && isSslReady()
    }

    private fun getPortString(request: HTTPRequest?, port: Int): String? {
        val standard_port = if (useSecure(request)) STANDARD_HTTPS_PORT else STANDARD_HTTP_PORT
        return if (port == standard_port) "" else ":$port"
    }

    private fun getPortString(request: HTTPRequest?, cache: Cache?): String? {
        val cache_port = if (useSecure(request)) cache.getHttpsPort() else cache.getPort()
        return getPortString(request, cache_port)
    }

    fun createURIString(request: HTTPRequest?, cache: Cache?): String? {
        var fqdn = getFQDN(cache)
        if (fqdn == null) {
            val cacheName: Array<String?> = cache.getFqdn().split(REGEX_PERIOD, 2.toBoolean()).toTypedArray()
            fqdn = cacheName[0].toString() + "." + request.getHostname().split(REGEX_PERIOD, 2.toBoolean())
                .toTypedArray()[1]
        }
        val port = if (useSecure(request)) cache.getHttpsPort() else cache.getPort()
        return createURIString(request, fqdn, port, getTransInfoStr(request))
    }

    private fun createURIString(request: HTTPRequest?, fqdn: String?, port: Int, tinfo: String?): String? {
        val uri = StringBuilder(if (useSecure(request)) "https://" else "http://")
        uri.append(fqdn)
        uri.append(getPortString(request, port))
        uri.append(request.getUri())
        var queryAppended = false
        if (request.getQueryString() != null && appendQueryString()) {
            uri.append('?').append(request.getQueryString())
            queryAppended = true
        }
        if (tinfo != null) {
            if (queryAppended) {
                uri.append('&')
            } else {
                uri.append('?')
            }
            uri.append(tinfo)
        }
        return uri.toString()
    }

    fun createURIString(request: HTTPRequest?, alternatePath: String?, cache: Cache?): String? {
        val uri = StringBuilder(if (useSecure(request)) "https://" else "http://")
        var fqdn = getFQDN(cache)
        if (fqdn == null) {
            val cacheName: Array<String?> = cache.getFqdn().split(REGEX_PERIOD, 2.toBoolean()).toTypedArray()
            fqdn = cacheName[0].toString() + "." + request.getHostname().split(REGEX_PERIOD, 2.toBoolean())
                .toTypedArray()[1]
        }
        uri.append(fqdn)
        uri.append(getPortString(request, cache))
        uri.append(alternatePath)
        return uri.toString()
    }

    fun getRemap(dsPattern: String?): String? {
        if (!dsPattern.contains(".*")) {
            return dsPattern
        }
        val host = wildcardPattern.matcher(dsPattern).replaceAll("") + "." + tld
        return if (isDns()) routingName + "." + host else host
    }

    private fun getFQDN(cache: Cache?): String? {
        for (dsRef in cache.getDeliveryServices()) {
            if (dsRef.deliveryServiceId == getId()) {
                return dsRef.fqdn
            }
        }
        return null
    }

    fun getFailureDnsResponse(request: DNSRequest?, track: StatTracker.Track?): MutableList<InetRecord?>? {
        if (bypassDestination == null) {
            track.setResult(ResultType.MISS)
            track.setResultDetails(ResultDetails.DS_NO_BYPASS)
            return null
        }
        track.setResult(ResultType.DS_REDIRECT)
        track.setResultDetails(ResultDetails.DS_BYPASS)
        return getRedirectInetRecords(bypassDestination["DNS"])
    }

    private var redirectInetRecords: MutableList<InetRecord?>? = null
    private fun getRedirectInetRecords(dns: JsonNode?): MutableList<InetRecord?>? {
        if (dns == null) {
            return null
        }
        if (redirectInetRecords != null) {
            return redirectInetRecords
        }
        try {
            synchronized(this) {
                val list: MutableList<InetRecord?> = ArrayList()
                val ttl = dns["ttl"].asInt() // we require a TTL to exist; will throw an exception if not present
                if (dns.has("ip") || dns.has("ip6")) {
                    if (dns.has("ip")) {
                        list.add(InetRecord(InetAddress.getByName(dns["ip"].asText()), ttl))
                    }
                    if (dns.has("ip6")) {
                        var ipStr = dns["ip6"].asText()
                        if (ipStr != null && !ipStr.isEmpty()) {
                            ipStr = ipStr.replace("/.*".toRegex(), "")
                            list.add(InetRecord(InetAddress.getByName(ipStr), ttl))
                        }
                    }
                } else if (dns.has("cname")) {
                    /*
					 * Per section 2.4 of RFC 1912 CNAMEs cannot coexist with other record types.
					 * As such, only add the CNAME if the above ip/ip6 keys do not exist
					 */
                    val cname = dns["cname"].asText()
                    if (cname != null) {
                        list.add(InetRecord(cname, ttl))
                    }
                }
                redirectInetRecords = list
            }
        } catch (e: Exception) {
            redirectInetRecords = null
            LOGGER.warn(e, e)
        }
        return redirectInetRecords
    }

    @JsonIgnore
    fun getSoa(): JsonNode? {
        return soa
    }

    fun isDns(): Boolean {
        return isDns
    }

    fun setDns(isDns: Boolean) {
        this.isDns = isDns
    }

    fun getDeepCache(): DeepCachingType? {
        return deepCache
    }

    fun appendQueryString(): Boolean {
        return shouldAppendQueryString
    }

    internal enum class TransInfoType {
        NONE, IP, IP_TID
    }

    fun getTransInfoStr(request: HTTPRequest?): String? {
        val type = TransInfoType.valueOf(getProp("transInfoType", "NONE"))
        if (type == TransInfoType.NONE) {
            return null
        }
        try {
            val ipBytes = getClientIpBytes(request, type) ?: return null
            return getEncryptedTrans(type, ipBytes)
        } catch (e: Exception) {
            LOGGER.warn(e, e)
        }
        return null
    }

    @Throws(UnknownHostException::class)
    private fun getClientIpBytes(request: HTTPRequest?, type: TransInfoType?): ByteArray? {
        val ip = InetAddress.getByName(request.getClientIP())
        var ipBytes = ip.address
        if (ipBytes.size > 4) {
            if (type == TransInfoType.IP) {
                return null
            }
            ipBytes = byteArrayOf(0, 0, 0, 0)
        }
        return ipBytes
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun getEncryptedTrans(type: TransInfoType?, ipBytes: ByteArray?): String? {
        ByteArrayOutputStream().use { baos ->
            DataOutputStream(baos).use { dos ->
                dos.write(ipBytes)
                if (type == TransInfoType.IP_TID) {
                    dos.writeLong(System.currentTimeMillis())
                    dos.writeInt(getTid())
                }
                dos.flush()
                return "t0=" + getStringProtector().encryptForUrl(baos.toByteArray())
            }
        }
    }

    private fun getProp(key: String?, d: String?): String? {
        return if (props == null || !props.has(key)) {
            d
        } else props[key].textValue()
    }

    private fun getProp(key: String?, d: Int): Int {
        return if (props == null || !props.has(key)) {
            d
        } else props[key].asInt()
    }

    private var isAvailable = true
    private var disabledLocations: JsonNode? = null
    fun setState(state: JsonNode?) {
        isAvailable = JsonUtils.optBoolean(state, "isAvailable", true)
        if (state != null) {
            // disabled locations
            disabledLocations = state["disabledLocations"]
        }
    }

    fun isAvailable(): Boolean {
        return isAvailable
    }

    fun isLocationAvailable(cl: Location?): Boolean {
        if (cl == null) {
            return false
        }
        val dls = disabledLocations ?: return true
        val locStr = cl.id
        for (curr in dls) {
            if (locStr == curr.asText()) {
                return false
            }
        }
        return true
    }

    fun getLocationLimit(): Int {
        return getProp("locationFailoverLimit", 0)
    }

    fun getMaxDnsIps(): Int {
        return getProp("maxDnsIpsForLocation", 0)
    }

    @JsonIgnore
    fun getStaticDnsEntries(): JsonNode? {
        return staticDnsEntries
    }

    fun getDomain(): String? {
        return domain
    }

    fun getRoutingName(): String? {
        return routingName
    }

    fun getTopology(): String? {
        return topology
    }

    fun hasRequiredCapabilities(serverCapabilities: MutableSet<String?>?): Boolean {
        return serverCapabilities.containsAll(requiredCapabilities)
    }

    fun getDispersion(): Dispersion? {
        return dispersion
    }

    fun getGeoRedirectUrl(): String? {
        return geoRedirectUrl
    }

    fun getGeoRedirectUrlType(): String? {
        return geoRedirectUrlType
    }

    fun setGeoRedirectUrlType(type: String?) {
        geoRedirectUrlType = type
    }

    fun getGeoRedirectFile(): String? {
        return geoRedirectFile
    }

    fun setGeoRedirectFile(filePath: String?) {
        geoRedirectFile = filePath
    }

    fun isIp6RoutingEnabled(): Boolean {
        return ip6RoutingEnabled
    }

    fun getResponseHeaders(): MutableMap<String?, String?>? {
        return responseHeaders
    }

    @Throws(JsonUtilsException::class)
    private fun setResponseHeaders(jo: JsonNode?) {
        if (jo != null) {
            val keyIter = jo.fieldNames()
            while (keyIter.hasNext()) {
                val key = keyIter.next()
                responseHeaders[key] = JsonUtils.getString(jo, key)
            }
        }
    }

    fun getRequestHeaders(): MutableSet<String?>? {
        return requestHeaders
    }

    private fun setRequestHeaders(jsonRequestHeaderNames: JsonNode?) {
        if (jsonRequestHeaderNames == null) {
            return
        }
        for (name in jsonRequestHeaderNames) {
            requestHeaders.add(name.asText())
        }
    }

    fun isRegionalGeoEnabled(): Boolean {
        return regionalGeoEnabled
    }

    fun getGeolocationProvider(): String? {
        return geolocationProvider
    }

    fun isAnonymousIpEnabled(): Boolean {
        return anonymousIpEnabled
    }

    fun filterAvailableLocations(cacheLocations: MutableCollection<CacheLocation?>?): MutableList<CacheLocation?>? {
        val locations: MutableList<CacheLocation?> = ArrayList()
        for (cl in cacheLocations) {
            if (isLocationAvailable(cl)) {
                locations.add(cl)
            }
        }
        return locations
    }

    fun isSslEnabled(): Boolean {
        return sslEnabled
    }

    fun setHasX509Cert(hasX509Cert: Boolean) {
        this.hasX509Cert = hasX509Cert
    }

    fun isSslReady(): Boolean {
        return sslEnabled && hasX509Cert
    }

    fun isAcceptHttp(): Boolean {
        return acceptHttp
    }

    fun getConsistentHashRegex(): String? {
        return consistentHashRegex
    }

    fun setConsistentHashRegex(consistentHashRegex: String?) {
        this.consistentHashRegex = consistentHashRegex
    }

    /**
     * Extracts the significant parts of a request's query string based on this
     * Delivery Service's Consistent Hashing Query Parameters
     * @param r The request from which to extract query parameters
     * @return The parts of the request's query string relevant to consistent
     * hashing. The result is URI-decoded - if decoding fails it will return
     * a blank string instead.
     */
    fun extractSignificantQueryParams(r: HTTPRequest?): String? {
        if (r.getQueryString() == null || r.getQueryString().isEmpty() || getConsistentHashQueryParams().isEmpty()) {
            return ""
        }
        val qparams: SortedSet<String?> = TreeSet()
        try {
            for (qparam in r.getQueryString().split("&").toTypedArray()) {
                if (qparam.isEmpty()) {
                    continue
                }
                val parts: Array<String?> = qparam.split("=").toTypedArray()
                for (i in parts.indices) {
                    parts[i] = URLDecoder.decode(parts[i], "UTF-8")
                }
                if (getConsistentHashQueryParams().contains(parts[0])) {
                    qparams.add(java.lang.String.join("=", *parts))
                }
            }
        } catch (e: UnsupportedEncodingException) {
            val err = StringBuffer()
            err.append("Error decoding query parameters - ")
            err.append(this.toString())
            err.append(" - Exception: ")
            err.append(e.toString())
            LOGGER.error(err.toString())
            return ""
        }
        val s = StringBuilder()
        for (q in qparams) {
            s.append(q)
        }
        return s.toString()
    }

    fun isEcsEnabled(): Boolean {
        return ecsEnabled
    }

    fun setEcsEnabled(ecsEnabled: Boolean) {
        this.ecsEnabled = ecsEnabled
    }

    companion object {
        protected val LOGGER = Logger.getLogger(DeliveryService::class.java)
        private const val STANDARD_HTTP_PORT = 80
        private const val STANDARD_HTTPS_PORT = 443
        private val REGEX_PERIOD: String? = "\\."
        var stringProtector: StringProtector? = null
        private fun getStringProtector(): StringProtector? {
            try {
                synchronized(LOGGER) {
                    if (stringProtector == null) {
                        stringProtector = StringProtector("HajUsyac7") // random passwd
                    }
                }
            } catch (e: GeneralSecurityException) {
                LOGGER.warn(e, e)
            }
            return stringProtector
        }

        var tid: AtomicInteger? = AtomicInteger(0)
        private fun getTid(): Int {
            return tid.incrementAndGet()
        }
    }

    init {
        ttls = props.get("ttls")
        if (ttls == null) {
            LOGGER.warn("ttls is null for:$id")
        }
        coverageZoneOnly = JsonUtils.getBoolean(props, "coverageZoneOnly")
        geoEnabled = props.get("geoEnabled")
        var rurl = JsonUtils.optString(props, "geoLimitRedirectURL", null)
        if (rurl != null && rurl.isEmpty()) {
            rurl = null
        }
        geoRedirectUrl = rurl
        geoRedirectUrlType = "INVALID_URL"
        geoRedirectFile = geoRedirectUrl
        staticDnsEntries = props.get("staticDnsEntries")
        bypassDestination = props.get("bypassDestination")
        routingName = JsonUtils.getString(props, "routingName").toLowerCase()
        domain = getDomainFromJson(props.get("domains"))
        tld = if (domain != null) domain.replace("^.*?\\.".toRegex(), "") else null
        soa = props.get("soa")
        shouldAppendQueryString = JsonUtils.optBoolean(props, "appendQueryString", true)
        ecsEnabled = optBoolean(props, "ecsEnabled")
        if (props.has("topology")) {
            topology = optString(props, "topology")
        }
        requiredCapabilities = HashSet()
        if (props.has("requiredCapabilities")) {
            val requiredCapabilitiesNode = props.get("requiredCapabilities")
            if (!requiredCapabilitiesNode.isArray) {
                LOGGER.error("Delivery Service '$id' has malformed requiredCapabilities. Disregarding.")
            } else {
                requiredCapabilitiesNode.forEach(Consumer { requiredCapabilityNode: JsonNode? ->
                    val requiredCapability = requiredCapabilityNode.asText()
                    if (!requiredCapability.isEmpty()) {
                        requiredCapabilities.add(requiredCapability)
                    }
                })
            }
        }
        consistentHashQueryParams = HashSet()
        if (props.has("consistentHashQueryParams")) {
            val cqpNode = props.get("consistentHashQueryParams")
            if (!cqpNode.isArray) {
                LOGGER.error("Delivery Service '$id' has malformed consistentHashQueryParams. Disregarding.")
            } else {
                for (n in cqpNode) {
                    val s = n.asText()
                    if (!s.isEmpty()) {
                        consistentHashQueryParams.add(s)
                    }
                }
            }
        }

        // missLocation: {lat: , long: }
        val mlJo = props.get("missLocation")
        missLocation = if (mlJo != null) {
            val lat: Double = optDouble(mlJo, "lat")
            val longitude: Double = optDouble(mlJo, "long")
            Geolocation(lat, longitude)
        } else {
            null
        }
        dispersion = Dispersion(props)
        ip6RoutingEnabled = optBoolean(props, "ip6RoutingEnabled")
        setResponseHeaders(props.get("responseHeaders"))
        setRequestHeaders(props.get("requestHeaders"))
        regionalGeoEnabled = optBoolean(props, "regionalGeoBlocking")
        geolocationProvider = optString(props, "geolocationProvider")
        if (geolocationProvider != null && !geolocationProvider.isEmpty()) {
            LOGGER.info("DeliveryService '$id' has configured geolocation provider '$geolocationProvider'")
        } else {
            LOGGER.info("DeliveryService '$id' will use default geolocation provider Maxmind")
        }
        sslEnabled = optBoolean(props, "sslEnabled")
        anonymousIpEnabled = optBoolean(props, "anonymousBlockingEnabled")
        consistentHashRegex = optString(props, "consistentHashRegex")
        val protocol = props.get("protocol")
        acceptHttp = JsonUtils.optBoolean(protocol, "acceptHttp", true)
        acceptHttps = optBoolean(protocol, "acceptHttps")
        redirectToHttps = optBoolean(protocol, "redirectToHttps")
        val dctString = JsonUtils.optString(props, "deepCachingType", "NEVER").toUpperCase()
        var dct = DeepCachingType.NEVER
        try {
            dct = DeepCachingType.valueOf(dctString)
        } catch (e: IllegalArgumentException) {
            LOGGER.error("DeliveryService '$id' has an unrecognized deepCachingType: '$dctString'. Defaulting to 'NEVER' instead")
        } finally {
            deepCache = dct
        }
    }
}