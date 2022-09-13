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
package org.apache.traffic_control.traffic_router.core.externalimport

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpHead
import org.apache.http.client.methods.HttpPost
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.ssl.SSLContextBuilder
import org.apache.traffic_control.traffic_router.core.util.ExternalTest
import org.apache.traffic_control.traffic_router.core.util.TrafficOpsUtils
import org.hamcrest.Matchers
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsNot
import org.junit.*
import org.junit.experimental.categories.Category
import org.junit.runners.MethodSorters
import org.xbill.DNS.*
import java.io.IOException
import java.net.*
import java.security.KeyStore
import java.util.*
import javax.net.ssl.*

org.springframework.web.bind.annotation .RequestMapping
import org.springframework.beans.factory.annotation.Autowired
import org.apache.traffic_control.traffic_router.core.util.DataExporter
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestMethod
import org.apache.traffic_control.traffic_router.core.status.model.CacheModel
import org.apache.traffic_control.traffic_router.core.ds.SteeringRegistry
import org.springframework.http.ResponseEntity
import org.apache.traffic_control.traffic_router.core.ds.Steering
import org.apache.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.apache.traffic_control.traffic_router.core.edge.CacheLocation
import org.apache.traffic_control.traffic_router.core.edge.Node.IPVersions
import org.apache.traffic_control.traffic_router.api.controllers.ConsistentHashController
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService
import org.apache.traffic_control.traffic_router.core.router.TrafficRouter
import org.apache.traffic_control.traffic_router.core.request.HTTPRequest
import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.traffic_control.traffic_router.core.ds.SteeringTarget
import org.apache.traffic_control.traffic_router.core.ds.SteeringFilter
import com.fasterxml.jackson.databind.JsonNode
import org.apache.traffic_control.traffic_router.core.ds.Dispersion
import org.apache.traffic_control.traffic_router.core.hash.DefaultHashable
import org.apache.traffic_control.traffic_router.geolocation.Geolocation
import com.fasterxml.jackson.annotation.JsonIgnore
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService.DeepCachingType
import org.apache.traffic_control.traffic_router.core.util.JsonUtilsException
import kotlin.Throws
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import java.lang.StringBuilder
import org.apache.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import org.apache.traffic_control.traffic_router.core.request.DNSRequest
import org.apache.traffic_control.traffic_router.core.edge.InetRecord
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.io.IOException
import java.security.GeneralSecurityException
import java.io.DataOutputStream
import java.lang.IllegalArgumentException
import java.io.UnsupportedEncodingException
import java.lang.StringBuffer
import org.apache.traffic_control.traffic_router.core.util.StringProtector
import java.util.concurrent.atomic.AtomicInteger
import org.apache.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import org.apache.traffic_control.traffic_router.core.ds.SteeringWatcher
import org.apache.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.core.JsonFactory
import org.apache.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import org.apache.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallenge
import org.apache.traffic_control.traffic_router.core.ds.SteeringResult
import org.apache.traffic_control.traffic_router.core.config.ConfigHandler
import org.apache.traffic_control.traffic_router.core.ds.LetsEncryptDnsChallengeWatcher
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.core.JsonParseException
import java.io.FileInputStream
import java.io.BufferedReader
import org.apache.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import org.apache.traffic_control.traffic_router.core.dns.protocol.TCP
import java.io.DataInputStream
import org.apache.traffic_control.traffic_router.core.dns.protocol.UDP
import org.apache.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import java.lang.Runnable
import java.util.concurrent.ExecutorService
import org.apache.traffic_control.traffic_router.core.dns.NameServer
import org.apache.traffic_control.traffic_router.core.dns.DNSAccessRecord
import org.apache.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.lang.InterruptedException
import org.apache.traffic_control.traffic_router.core.dns.ZoneKey
import org.apache.traffic_control.traffic_router.core.dns.RRsetKey
import java.text.SimpleDateFormat
import org.apache.traffic_control.traffic_router.core.dns.ZoneUtils
import java.lang.RuntimeException
import org.apache.traffic_control.traffic_router.core.dns.ZoneManager
import org.apache.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import java.util.concurrent.ConcurrentMap
import org.apache.traffic_control.traffic_router.core.dns.RRSIGCacheKey
import org.apache.traffic_control.traffic_router.core.router.StatTracker
import org.apache.traffic_control.traffic_router.core.edge.CacheRegister
import org.apache.traffic_control.traffic_router.core.dns.SignatureManager
import org.apache.traffic_control.traffic_router.core.router.DNSRouteResult
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import org.apache.traffic_control.traffic_router.core.dns.ZoneManager.ZoneCacheType
import java.util.concurrent.Callable
import java.util.stream.Collectors
import com.google.common.cache.CacheBuilderSpec
import java.io.FileWriter
import com.google.common.cache.RemovalListener
import com.google.common.cache.RemovalNotification
import com.google.common.cache.CacheBuilder
import com.google.common.cache.CacheLoader
import org.apache.traffic_control.traffic_router.core.dns.SignedZoneKey
import java.security.NoSuchAlgorithmException
import org.apache.traffic_control.traffic_router.geolocation.GeolocationException
import org.apache.traffic_control.traffic_router.core.edge.TrafficRouterLocation
import java.security.PrivateKey
import java.security.PublicKey
import org.apache.traffic_control.traffic_router.core.dns.RRSetsBuilder
import java.util.function.ToLongFunction
import org.apache.traffic_control.traffic_router.core.dns.NameServerMain
import kotlin.jvm.JvmStatic
import org.springframework.context.support.ClassPathXmlApplicationContext
import org.apache.traffic_control.traffic_router.core.dns.ZoneSigner
import java.util.stream.StreamSupport
import org.xbill.DNS.DNSSEC.DNSSECException
import org.apache.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import java.util.function.BiFunction
import java.util.function.ToIntFunction
import org.apache.traffic_control.traffic_router.core.util.ProtectedFetcher
import org.apache.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import java.util.function.BinaryOperator
import org.apache.traffic_control.traffic_router.secure.BindPrivateKey
import java.io.ByteArrayInputStream
import java.text.DecimalFormat
import java.math.RoundingMode
import org.apache.traffic_control.traffic_router.core.loc.FederationMapping
import org.apache.traffic_control.traffic_router.core.loc.Federation
import org.apache.traffic_control.traffic_router.core.util.CidrAddress
import org.apache.traffic_control.traffic_router.core.loc.AnonymousIpWhitelist
import org.apache.traffic_control.traffic_router.core.loc.NetworkNodeException
import org.apache.traffic_control.traffic_router.core.loc.AnonymousIp
import com.google.common.net.InetAddresses
import com.maxmind.geoip2.model.AnonymousIpResponse
import org.apache.traffic_control.traffic_router.core.router.HTTPRouteResult
import kotlin.jvm.JvmOverloads
import org.apache.traffic_control.traffic_router.core.loc.NetworkNode
import org.apache.traffic_control.traffic_router.core.loc.NetworkNode.SuperNode
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoDsvc
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoRule
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeo
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoRule.PostalsType
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoCoordinateRange
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoResult
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoResult.RegionalGeoResultType
import org.apache.traffic_control.traffic_router.core.loc.AbstractServiceUpdater
import org.apache.traffic_control.traffic_router.core.util.ComparableTreeSet
import org.apache.traffic_control.traffic_router.core.loc.NetworkUpdater
import org.apache.traffic_control.traffic_router.core.loc.FederationMappingBuilder
import org.apache.traffic_control.traffic_router.core.loc.FederationRegistry
import org.apache.traffic_control.traffic_router.core.loc.FederationsWatcher
import org.apache.traffic_control.traffic_router.core.loc.FederationsBuilder
import org.apache.traffic_control.traffic_router.core.loc.RegionalGeoUpdater
import java.nio.file.Path
import java.io.FileOutputStream
import java.util.zip.GZIPInputStream
import org.apache.traffic_control.traffic_router.core.loc.AnonymousIpConfigUpdater
import org.apache.traffic_control.traffic_router.geolocation.GeolocationService
import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.model.CityResponse
import com.maxmind.geoip2.exception.AddressNotFoundException
import org.apache.traffic_control.traffic_router.core.loc.MaxmindGeolocationService
import org.apache.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseService
import com.maxmind.geoip2.exception.GeoIp2Exception
import org.apache.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseUpdater
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.apache.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import org.apache.traffic_control.traffic_router.core.hash.Hashable
import org.apache.traffic_control.traffic_router.core.hash.NumberSearcher
import org.apache.traffic_control.traffic_router.core.hash.MD5HashFunction
import org.springframework.web.filter.OncePerRequestFilter
import org.apache.traffic_control.traffic_router.core.http.HTTPAccessRecord
import org.apache.traffic_control.traffic_router.core.http.RouterFilter
import org.apache.traffic_control.traffic_router.core.http.HTTPAccessEventBuilder
import org.apache.traffic_control.traffic_router.core.http.HttpAccessRequestHeaders
import org.apache.traffic_control.traffic_router.core.util.Fetcher.DefaultTrustManager
import java.lang.NumberFormatException
import org.apache.traffic_control.traffic_router.core.util.FederationExporter
import org.apache.traffic_control.traffic_router.core.edge.PropertiesAndCaches
import org.apache.traffic_control.traffic_router.core.util.LanguidState
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import org.apache.traffic_control.traffic_router.core.util.ResourceUrl
import org.apache.traffic_control.traffic_router.core.config.WatcherConfig
import java.io.FileReader
import org.apache.traffic_control.traffic_router.core.util.AbstractUpdatable
import org.asynchttpclient.AsyncHttpClient
import org.apache.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
import org.asynchttpclient.DefaultAsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClientConfig
import org.asynchttpclient.AsyncCompletionHandler
import org.apache.traffic_control.traffic_router.core.util.ComparableStringByLength
import org.apache.traffic_control.traffic_router.core.loc.GeolocationDatabaseUpdater
import org.apache.traffic_control.traffic_router.core.loc.DeepNetworkUpdater
import org.apache.traffic_control.traffic_router.core.secure.CertificatesPoller
import org.apache.traffic_control.traffic_router.core.secure.CertificatesPublisher
import java.util.concurrent.atomic.AtomicBoolean
import org.apache.traffic_control.traffic_router.core.monitor.TrafficMonitorWatcher
import org.apache.traffic_control.traffic_router.shared.CertificateData
import org.apache.traffic_control.traffic_router.core.config.CertificateChecker
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.RouteType
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultCode
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Tallies
import org.apache.traffic_control.traffic_router.core.hash.ConsistentHasher
import org.springframework.web.util.UriComponentsBuilder
import org.apache.traffic_control.traffic_router.core.ds.SteeringGeolocationComparator
import org.apache.traffic_control.traffic_router.core.router.LocationComparator
import org.springframework.beans.BeansException
import org.apache.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import org.apache.traffic_control.traffic_router.core.secure.CertificatesClient
import org.apache.traffic_control.traffic_router.core.secure.CertificatesResponse
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import javax.management.ObjectName
import org.apache.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.fasterxml.jackson.core.JsonProcessingException
import org.apache.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import org.springframework.context.event.ContextClosedEvent
import org.powermock.reflect.Whitebox
import org.powermock.core.classloader.annotations.PrepareForTest
import org.junit.runner.RunWith
import org.powermock.modules.junit4.PowerMockRunner
import org.powermock.core.classloader.annotations.PowerMockIgnore
import org.mockito.Mockito
import org.apache.traffic_control.traffic_router.shared.ZoneTestRecords
import org.mockito.ArgumentMatchers
import org.powermock.api.mockito.PowerMockito
import org.mockito.stubbing.Answer
import org.mockito.invocation.InvocationOnMock
import org.apache.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest.FakeAbstractProtocol
import java.lang.System
import org.apache.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import org.apache.traffic_control.traffic_router.core.util.IntegrationTest
import org.apache.traffic_control.traffic_router.core.dns.ZoneManagerTest
import org.apache.traffic_control.traffic_router.core.TestBase
import org.apache.traffic_control.traffic_router.core.dns.DNSException
import org.mockito.ArgumentMatcher
import org.apache.traffic_control.traffic_router.core.dns.ZoneSignerImplTest.IsRRsetTypeA
import org.apache.traffic_control.traffic_router.core.dns.ZoneSignerImplTest.IsRRsetTypeNSEC
import org.apache.traffic_control.traffic_router.core.loc.GeoTest
import org.apache.traffic_control.traffic_router.core.loc.NetworkNodeTest
import org.apache.traffic_control.traffic_router.core.loc.MaxmindGeoIP2Test
import org.powermock.api.support.membermodification.MemberModifier
import org.powermock.api.support.membermodification.MemberMatcher
import org.apache.traffic_control.traffic_router.core.loc.AbstractServiceUpdaterTest.Updater
import org.apache.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseServiceTest
import org.apache.traffic_control.traffic_router.core.util.AbstractResourceWatcherTest
import java.lang.Void
import org.apache.traffic_control.traffic_router.core.router.StatelessTrafficRouterTest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.apache.traffic_control.traffic_router.secure.Pkcs1
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import org.mockito.Mock
import org.mockito.InjectMocks
import org.mockito.MockitoAnnotations
import org.apache.traffic_control.traffic_router.core.util.ExternalTest
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.catalina.LifecycleException
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.util.EntityUtils
import org.junit.runners.MethodSorters
import java.security.KeyStore
import org.apache.traffic_control.traffic_router.core.external.RouterTest.ClientSslSocketFactory
import org.apache.traffic_control.traffic_router.core.external.RouterTest.TestHostnameVerifier
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpHead
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.hamcrest.number.IsCloseTo
import com.sun.net.httpserver.HttpExchange
import org.junit.runners.Suite
import org.junit.runners.Suite.SuiteClasses
import org.apache.traffic_control.traffic_router.core.external.SteeringTest
import org.apache.traffic_control.traffic_router.core.external.ConsistentHashTest
import org.apache.traffic_control.traffic_router.core.external.DeliveryServicesTest
import org.apache.traffic_control.traffic_router.core.external.LocationsTest
import org.apache.traffic_control.traffic_router.core.external.RouterTest
import org.apache.traffic_control.traffic_router.core.external.StatsTest
import org.apache.traffic_control.traffic_router.core.external.ZonesTest
import org.apache.traffic_control.traffic_router.core.CatalinaTrafficRouter
import org.apache.traffic_control.traffic_router.core.external.HttpDataServer
import org.apache.traffic_control.traffic_router.core.external.ExternalTestSuite
import org.apache.logging.log4j.core.appender.ConsoleAppender
import org.apache.logging.log4j.core.layout.PatternLayout
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.FileVisitResult
import org.hamcrest.number.OrderingComparison
import javax.management.MBeanServer
import org.apache.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import org.springframework.context.support.FileSystemXmlApplicationContext
import org.apache.catalina.startup.Catalina
import org.apache.catalina.core.StandardService
import org.apache.catalina.core.StandardHost
import org.apache.catalina.core.StandardContext
import java.security.Security
import org.apache.traffic_control.traffic_router.secure.Pkcs
import org.apache.traffic_control.traffic_router.secure.Pkcs1KeySpecDecoder
import org.apache.traffic_control.traffic_router.secure.Pkcs8
import java.security.spec.RSAPrivateCrtKeySpec
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1SequenceParser
import org.bouncycastle.asn1.ASN1Integer
import java.security.spec.RSAPublicKeySpec
import org.apache.traffic_control.traffic_router.shared.SigningData
import java.security.NoSuchProviderException
import java.security.KeyPairGenerator
import org.apache.traffic_control.traffic_router.shared.IsEqualCollection
import javax.management.NotificationBroadcasterSupport
import javax.management.AttributeChangeNotification
import java.security.interfaces.RSAPrivateCrtKey
import org.mockito.ArgumentCaptor
import org.apache.traffic_control.traffic_router.utils.HttpsProperties
import java.nio.file.Paths
import org.apache.traffic_control.traffic_router.secure.CertificateRegistry
import java.security.Principal
import java.lang.UnsupportedOperationException
import org.apache.traffic_control.traffic_router.secure.HandshakeData
import org.apache.traffic_control.traffic_router.secure.CertificateDecoder
import org.apache.traffic_control.traffic_router.secure.CertificateDataConverter
import kotlin.jvm.Volatile
import org.apache.traffic_control.traffic_router.protocol.RouterNioEndpoint
import org.apache.traffic_control.traffic_router.secure.CertificateRegistry.CertificateRegistryHolder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import javax.management.NotificationListener
import org.apache.traffic_control.traffic_router.secure.CertificateDataListener
import org.apache.traffic_control.traffic_router.secure.PrivateKeyDecoder
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
import org.apache.catalina.LifecycleListener
import org.apache.catalina.LifecycleEvent
import org.apache.traffic_control.traffic_router.tomcat.TomcatLifecycleListener
import org.apache.traffic_control.traffic_router.protocol.RouterProtocolHandler
import org.apache.traffic_control.traffic_router.protocol.LanguidPoller
import org.apache.tomcat.util.net.SSLHostConfigCertificate
import org.apache.tomcat.util.net.SSLUtilBase
import org.apache.traffic_control.traffic_router.protocol.RouterSslUtil
import org.apache.tomcat.util.net.openssl.OpenSSLEngine
import org.apache.tomcat.util.net.openssl.OpenSSLContext
import org.apache.coyote.http11.Http11NioProtocol
import org.apache.traffic_control.traffic_router.protocol.LanguidProtocol
import org.apache.tomcat.util.net.NioEndpoint
import org.apache.tomcat.util.net.SSLHostConfig
import org.apache.coyote.http11.AbstractHttp11JsseProtocol
import org.apache.tomcat.util.net.NioChannel
import org.apache.traffic_control.traffic_router.protocol.LanguidNioProtocol
import java.lang.ClassNotFoundException
import org.apache.coyote.ProtocolHandler
import org.apache.tomcat.util.net.SSLImplementation
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.jsse.JSSESupport
import org.apache.tomcat.util.net.SSLUtil
import secure.KeyManagerTest.TestSNIServerName
import secure.CertificateDataConverterTest
import org.apache.traffic_control.traffic_router.protocol.RouterSslImplementation

@Category(ExternalTest::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class RouterTest {
    private var httpClient: CloseableHttpClient? = null
    private val cdnDomain: String? = ".thecdn.example.com"
    private var deliveryServiceId: String? = null
    private var deliveryServiceDomain: String? = null
    private val validLocations: MutableList<String?>? = ArrayList()
    private val httpsOnlyId: String? = "https-only-test"
    private val httpsOnlyDomain: String? = httpsOnlyId + cdnDomain
    private val httpsOnlyLocations: MutableList<String?>? = ArrayList()
    private val httpsNoCertsId: String? = "https-nocert"
    private val httpsNoCertsDomain: String? = httpsNoCertsId + cdnDomain
    private val httpsNoCertsLocations: MutableList<String?>? = ArrayList()
    private val httpAndHttpsId: String? = "http-and-https-test"
    private val httpAndHttpsDomain: String? = httpAndHttpsId + cdnDomain
    private val httpAndHttpsLocations: MutableList<String?>? = ArrayList()
    private val httpToHttpsId: String? = "http-to-https-test"
    private val httpToHttpsDomain: String? = httpToHttpsId + cdnDomain
    private val httpToHttpsLocations: MutableList<String?>? = ArrayList()
    private val httpOnlyId: String? = "http-only-test"
    private val httpOnlyDomain: String? = httpOnlyId + cdnDomain
    private val httpOnlyLocations: MutableList<String?>? = ArrayList()
    private val routerHttpPort = System.getProperty("routerHttpPort", "8888")
    private val routerSecurePort = System.getProperty("routerSecurePort", "8443")
    private val testHttpPort = System.getProperty("testHttpServerPort", "8889")
    private var trustStore: KeyStore? = null
    private val routerDnsPort = Integer.valueOf(System.getProperty("dns.udp.port", "1053"))
    @Before
    @Throws(Exception::class)
    fun before() {
        val objectMapper = ObjectMapper(JsonFactory())
        var resourcePath = "api/" + TrafficOpsUtils.Companion.TO_API_VERSION + "/steering"
        var inputStream = javaClass.classLoader.getResourceAsStream(resourcePath)
        if (inputStream == null) {
            Assert.fail("Could not find file '$resourcePath' needed for test from the current classpath as a resource!")
        }
        val steeringDeliveryServices: MutableSet<String?> = HashSet()
        val steeringData = objectMapper.readTree(inputStream)["response"]
        val elements = steeringData.elements()
        while (elements.hasNext()) {
            val ds = elements.next()
            val dsId = ds["deliveryService"].asText()
            steeringDeliveryServices.add(dsId)
        }
        resourcePath = "publish/CrConfig.json"
        inputStream = javaClass.classLoader.getResourceAsStream(resourcePath)
        if (inputStream == null) {
            Assert.fail("Could not find file '$resourcePath' needed for test from the current classpath as a resource!")
        }
        val jsonNode = objectMapper.readTree(inputStream)
        deliveryServiceId = null
        val deliveryServices = jsonNode["deliveryServices"].fieldNames()
        while (deliveryServices.hasNext()) {
            val dsId = deliveryServices.next()
            if (steeringDeliveryServices.contains(dsId)) {
                continue
            }
            val deliveryServiceNode = jsonNode["deliveryServices"][dsId]
            val matchsets = deliveryServiceNode["matchsets"].iterator()
            while (matchsets.hasNext() && deliveryServiceId == null) {
                if ("HTTP" == matchsets.next()["protocol"].asText()) {
                    val sslEnabled: Boolean = optBoolean(deliveryServiceNode, "sslEnabled")
                    if (!sslEnabled) {
                        deliveryServiceId = dsId
                        deliveryServiceDomain = deliveryServiceNode["domains"][0].asText()
                    }
                }
            }
        }
        Assert.assertThat(deliveryServiceId, IsNot.not(Matchers.nullValue()))
        Assert.assertThat(deliveryServiceDomain, IsNot.not(Matchers.nullValue()))
        Assert.assertThat(httpsOnlyId, IsNot.not(Matchers.nullValue()))
        Assert.assertThat(httpsOnlyDomain, IsNot.not(Matchers.nullValue()))
        val cacheIds = jsonNode["contentServers"].fieldNames()
        while (cacheIds.hasNext()) {
            val cacheId = cacheIds.next()
            val cacheNode = jsonNode["contentServers"][cacheId]
            if (!cacheNode.has("deliveryServices")) {
                continue
            }
            if (cacheNode["deliveryServices"].has(deliveryServiceId)) {
                val port = cacheNode["port"].asInt()
                val portText = if (port == 80) "" else ":$port"
                validLocations.add("http://$cacheId.$deliveryServiceDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
                validLocations.add("http://$cacheId.$deliveryServiceDomain$portText/stuff?fakeClientIpAddress=12.34.56.78&format=json")
            }
            if (cacheNode["deliveryServices"].has(httpsOnlyId)) {
                val port = if (cacheNode.has("httpsPort")) cacheNode["httpsPort"].asInt(443) else 443
                val portText = if (port == 443) "" else ":$port"
                httpsOnlyLocations.add("https://$cacheId.$httpsOnlyDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
            }
            if (cacheNode["deliveryServices"].has(httpsNoCertsId)) {
                val port = if (cacheNode.has("httpsPort")) cacheNode["httpsPort"].asInt(443) else 443
                val portText = if (port == 443) "" else ":$port"
                httpsNoCertsLocations.add("https://$cacheId.$httpsNoCertsDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
            }
            if (cacheNode["deliveryServices"].has(httpAndHttpsId)) {
                var port = if (cacheNode.has("httpsPort")) cacheNode["httpsPort"].asInt(443) else 443
                var portText = if (port == 443) "" else ":$port"
                httpAndHttpsLocations.add("https://$cacheId.$httpAndHttpsDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
                port = if (cacheNode.has("port")) cacheNode["port"].asInt(80) else 80
                portText = if (port == 80) "" else ":$port"
                httpAndHttpsLocations.add("http://$cacheId.$httpAndHttpsDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
            }
            if (cacheNode["deliveryServices"].has(httpToHttpsId)) {
                val port = if (cacheNode.has("httpsPort")) cacheNode["httpsPort"].asInt(443) else 443
                val portText = if (port == 443) "" else ":$port"
                httpToHttpsLocations.add("https://$cacheId.$httpToHttpsDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
            }
            if (cacheNode["deliveryServices"].has(httpOnlyId)) {
                val port = if (cacheNode.has("port")) cacheNode["port"].asInt(80) else 80
                val portText = if (port == 80) "" else ":$port"
                httpOnlyLocations.add("http://$cacheId.$httpOnlyDomain$portText/stuff?fakeClientIpAddress=12.34.56.78")
            }
        }
        Assert.assertThat(validLocations.isEmpty(), IsEqual.equalTo(false))
        Assert.assertThat(httpsOnlyLocations.isEmpty(), IsEqual.equalTo(false))
        trustStore = KeyStore.getInstance(KeyStore.getDefaultType())
        val keystoreStream = javaClass.classLoader.getResourceAsStream("keystore.jks")
        trustStore.load(keystoreStream, "changeit".toCharArray())
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).init(trustStore)
        httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(ClientSslSocketFactory("tr.https-only-test.thecdn.example.com"))
                .setSSLHostnameVerifier(TestHostnameVerifier())
                .disableRedirectHandling()
                .build()
    }

    @After
    @Throws(IOException::class)
    fun after() {
        if (httpClient != null) {
            httpClient.close()
        }
    }

    @Test
    @Throws(TextParseException::class, UnknownHostException::class)
    fun itAUsesEdgeTrafficRoutersForHttpRouting() {
        val edgeIpAddresses: MutableSet<String?> = HashSet()
        // this will actually be the "miss" scenario since the resolver is localhost, which will be a CZF miss
        // in the miss case, we serve one TR from each location, and these are what we'd serve with our test CrConfig.json
        edgeIpAddresses.add("12.34.21.2")
        edgeIpAddresses.add("12.34.21.3")
        edgeIpAddresses.add("12.34.21.7")
        edgeIpAddresses.add("12.34.21.8")
        edgeIpAddresses.add("2001:dead:beef:124:1:0:0:2")
        edgeIpAddresses.add("2001:dead:beef:124:1:0:0:3")
        edgeIpAddresses.add("2001:dead:beef:124:1:0:0:7")
        edgeIpAddresses.add("2001:dead:beef:124:1:0:0:8")
        val resolver = SimpleResolver("localhost")
        resolver.setPort(routerDnsPort)
        for (type in Arrays.asList(Type.A, Type.AAAA)) {
            val lookup = Lookup(Name("tr.http-only-test.thecdn.example.com."), type)
            lookup.setResolver(resolver)
            lookup.run()
            Assert.assertThat(lookup.result, IsEqual.equalTo(Lookup.SUCCESSFUL))
            Assert.assertThat(lookup.answers.size, IsEqual.equalTo(4))
            for (record in lookup.answers) {
                Assert.assertThat(record.rdataToString(), Matchers.isIn(edgeIpAddresses))
            }
        }
    }

    @Test
    @Throws(IOException::class, InterruptedException::class)
    fun itRedirectsValidHttpRequests() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$deliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val header = response.getFirstHeader("Location")
            Assert.assertThat(header.value, Matchers.isIn(validLocations))
            Assert.assertThat(header.value, Matchers.startsWith("http://"))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itDoesRoutingThroughPathsStartingWithCrs() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/crs/stats?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "foo.$deliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(IOException::class, InterruptedException::class)
    fun itConsistentlyRedirectsValidRequests() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$deliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val location = response.getFirstHeader("Location").value
            response.close()
            for (i in 0..99) {
                response = httpClient.execute(httpGet)
                Assert.assertThat(response.getFirstHeader("Location").value, IsEqual.equalTo(location))
                response.close()
            }
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(IOException::class)
    fun itRejectsInvalidRequests() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "foo.invalid-delivery-service-id.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(503))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itRedirectsHttpsRequests() {
        val httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpsOnlyId.thecdn.example.com")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val header = response.getFirstHeader("Location")
            Assert.assertThat(header.value, Matchers.isIn(httpsOnlyLocations))
            Assert.assertThat(header.value, Matchers.startsWith("https://"))
            Assert.assertThat(header.value, Matchers.containsString("$httpsOnlyId.thecdn.example.com/stuff"))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itRejectsHttpRequestsForHttpsOnlyDeliveryService() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpsOnlyId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(503))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itRedirectsFromHttpToHttps() {
        var httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpToHttpsId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val header = response.getFirstHeader("Location")
            Assert.assertThat(header.value, Matchers.isIn(httpToHttpsLocations))
            Assert.assertThat(header.value, Matchers.startsWith("https://"))
            Assert.assertThat(header.value, Matchers.containsString("$httpToHttpsId.thecdn.example.com"))
            Assert.assertThat(header.value, Matchers.containsString("/stuff"))
        }
        httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(ClientSslSocketFactory("tr.http-and-https-test.thecdn.example.com"))
                .setSSLHostnameVerifier(TestHostnameVerifier())
                .disableRedirectHandling()
                .build()
        httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpToHttpsId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val header = response.getFirstHeader("Location")
            Assert.assertThat(header.value, Matchers.isIn(httpToHttpsLocations))
            Assert.assertThat(header.value, Matchers.startsWith("https://"))
            Assert.assertThat(header.value, Matchers.containsString("$httpToHttpsId.thecdn.example.com"))
            Assert.assertThat(header.value, Matchers.containsString("/stuff"))
        }
    }

    @Test
    @Throws(Exception::class)
    fun itRejectsHttpsRequestsForHttpDeliveryService() {
        val httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$deliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat("Response 503 expected got" + response.statusLine.statusCode, response.statusLine.statusCode, IsEqual.equalTo(503))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itPreservesProtocolForHttpAndHttps() {
        var httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpAndHttpsId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val header = response.getFirstHeader("Location")
            Assert.assertThat(header.value, Matchers.isIn(httpAndHttpsLocations))
            Assert.assertThat(header.value, Matchers.startsWith("http://"))
            Assert.assertThat(header.value, Matchers.containsString("$httpAndHttpsId.thecdn.example.com"))
            Assert.assertThat(header.value, Matchers.containsString("/stuff"))
        }
        httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(ClientSslSocketFactory("tr.http-and-https-test.thecdn.example.com"))
                .setSSLHostnameVerifier(TestHostnameVerifier())
                .disableRedirectHandling()
                .build()
        httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpAndHttpsId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val header = response.getFirstHeader("Location")
            Assert.assertThat(header.value, Matchers.isIn(httpAndHttpsLocations))
            Assert.assertThat(header.value, Matchers.startsWith("https://"))
            Assert.assertThat(header.value, Matchers.containsString("$httpAndHttpsId.thecdn.example.com"))
            Assert.assertThat(header.value, Matchers.containsString("/stuff"))
        }
    }

    @Test
    @Throws(Exception::class)
    fun itRejectsCrConfigWithMissingCert() {
        var httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpOnlyId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            Assert.assertThat(response.getFirstHeader("Location").value, Matchers.isOneOf(
                    "http://edge-cache-000.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-001.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-002.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78"
            ))
        }
        httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(ClientSslSocketFactory(httpsNoCertsDomain))
                .setSSLHostnameVerifier(TestHostnameVerifier())
                .disableRedirectHandling()
                .build()
        httpGet = HttpGet("https://localhost:$routerSecurePort/x?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpsNoCertsId.bar")
        try {
            httpClient.execute(httpGet).use { response ->
                val code = response.statusLine.statusCode
                Assert.assertThat("Expected a server error code (503) But got: $code",
                        code, Matchers.greaterThan(500))
            }
        } catch (she: SSLHandshakeException) {
            // Expected result of getting the self-signed _default_ certificate
        }

        // Pretend someone did a cr-config snapshot that would have updated the location to be different
        var httpPost = HttpPost("http://localhost:$testHttpPort/crconfig-2")
        httpClient.execute(httpPost).close()

        // Default interval for polling cr config is 10 seconds
        Thread.sleep((15 * 1000).toLong())
        httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpOnlyId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val location = response.getFirstHeader("Location").value
            Assert.assertThat(location, IsNot.not(Matchers.isOneOf(
                    "http://edge-cache-010.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-011.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-012.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78"
            )))
        }


        // verify that if we get a new cr-config that turns off https for the problematic delivery service
        // that it's able to get through while TR is still concurrently trying to get certs
        var testHttpPort = System.getProperty("testHttpServerPort", "8889")
        httpPost = HttpPost("http://localhost:$testHttpPort/crconfig-3")
        httpClient.execute(httpPost).close()

        // Default interval for polling cr config is 10 seconds
        Thread.sleep((30 * 1000).toLong())
        httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpOnlyId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val location = response.getFirstHeader("Location").value
            Assert.assertThat(location, Matchers.isOneOf(
                    "http://edge-cache-010.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-011.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-012.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78"
            ))
        }

        // assert that request gets rejected because SSL is turned off
        httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpsNoCertsId.bar")
        try {
            httpClient.execute(httpGet).use { response ->
                val code = response.statusLine.statusCode
                Assert.assertThat("Expected an server error code! But got: $code",
                        code, Matchers.greaterThan(500))
            }
        } catch (she: SSLHandshakeException) {
            // expected result of getting the self-signed _default_ certificate
        }

        // Go back to the cr-config that makes the delivery service https again
        // Pretend someone did a cr-config snapshot that would have updated the location to be different
        httpPost = HttpPost("http://localhost:$testHttpPort/crconfig-4")
        httpClient.execute(httpPost).close()

        // Default interval for polling cr config is 10 seconds
        Thread.sleep((15 * 1000).toLong())

        // Update certificates so new ds is valid
        testHttpPort = System.getProperty("testHttpServerPort", "8889")
        httpPost = HttpPost("http://localhost:$testHttpPort/certificates")
        httpClient.execute(httpPost).close()
        httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(ClientSslSocketFactory("https-additional"))
                .setSSLHostnameVerifier(TestHostnameVerifier())
                .disableRedirectHandling()
                .build()
        // Our initial test cr config data sets cert poller to 10 seconds
        Thread.sleep(25000L)
        httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr." + "https-additional" + ".bar")
        try {
            httpClient.execute(httpGet).use { response ->
                val code = response.statusLine.statusCode
                Assert.assertThat("Expected an server error code! But got: $code",
                        code, IsEqual.equalTo(302))
            }
        } catch (e: SSLHandshakeException) {
            Assert.fail(e.message)
        }
        httpGet = HttpGet("https://localhost:$routerSecurePort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpsNoCertsId.bar")
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val location = response.getFirstHeader("Location").value
            Assert.assertThat(location, Matchers.isOneOf(
                    "https://edge-cache-090.https-nocert.thecdn.example.com/stuff?fakeClientIpAddress=12.34.56.78",
                    "https://edge-cache-091.https-nocert.thecdn.example.com/stuff?fakeClientIpAddress=12.34.56.78",
                    "https://edge-cache-092.https-nocert.thecdn.example.com/stuff?fakeClientIpAddress=12.34.56.78"
            ))
        }
        httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "tr.$httpOnlyId.bar")
        println(httpGet.toString())
        println(Arrays.toString(httpGet.allHeaders))
        httpClient.execute(httpGet).use { response ->
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(302))
            val location = response.getFirstHeader("Location").value
            Assert.assertThat(location, Matchers.isOneOf(
                    "http://edge-cache-010.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-011.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78",
                    "http://edge-cache-012.http-only-test.thecdn.example.com:8090/stuff?fakeClientIpAddress=12.34.56.78"
            ))
        }
    }

    @Test
    @Throws(IOException::class, InterruptedException::class)
    fun itDoesUseLocationFormatResponse() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78&format=json")
        httpGet.addHeader("Host", "tr.$deliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(200))
            val entity = response.entity
            val objectMapper = ObjectMapper(JsonFactory())
            Assert.assertThat(entity.content, IsNot.not(Matchers.nullValue()))
            val json = objectMapper.readTree(entity.content)
            Assert.assertThat(json.has("location"), IsEqual.equalTo(true))
            Assert.assertThat(json["location"].asText(), Matchers.isIn(validLocations))
            Assert.assertThat(json["location"].asText(), Matchers.startsWith("http://"))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(IOException::class, InterruptedException::class)
    fun itDoesNotUseLocationFormatResponseForHead() {
        val httpHead = HttpHead("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78&format=json")
        httpHead.addHeader("Host", "tr.$deliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpHead)
            Assert.assertThat(response.statusLine.statusCode, IsEqual.equalTo(200))
            Assert.assertThat("Failed getting null body for HEAD request", response.entity, Matchers.nullValue())
        } finally {
            response?.close()
        }
    }

    // This is a workaround to get HttpClient to do the equivalent of
    // curl -v --resolve 'tr.https-only-test.thecdn.cdnlab.example.com:8443:127.0.0.1' https://tr.https-only-test.thecdn.example.com:8443/foo.json
    internal inner class ClientSslSocketFactory(private val host: String?) : SSLConnectionSocketFactory(SSLContextBuilder.create().loadTrustMaterial(trustStore, TrustSelfSignedStrategy()).build(),
            TestHostnameVerifier()) {
        @Throws(IOException::class)
        override fun prepareSocket(sslSocket: SSLSocket?) {
            val serverName = SNIHostName(host)
            val serverNames: MutableList<SNIServerName?> = ArrayList(1)
            serverNames.add(serverName)
            val params = sslSocket.getSSLParameters()
            params.serverNames = serverNames
            sslSocket.setSSLParameters(params)
        }
    }

    // This is a workaround for the same reason as above
    // org.apache.http.conn.ssl.SSLConnectionSocketFactory.verifyHostname(<socket>, 'localhost') normally fails
    internal inner class TestHostnameVerifier : HostnameVerifier {
        override fun verify(s: String?, sslSession: SSLSession?): Boolean {
            Assert.assertThat("s = " + s + ", getPeerHost() = " + sslSession.getPeerHost(), sslSession.getPeerHost(), IsEqual.equalTo(s))
            return sslSession.getPeerHost() == s
        }
    }
}