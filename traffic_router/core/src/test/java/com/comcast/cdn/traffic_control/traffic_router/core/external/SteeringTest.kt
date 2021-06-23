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
package com.comcast.cdn.traffic_control.traffic_router.core.external

import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.beans.factory.annotation.Autowired
import com.comcast.cdn.traffic_control.traffic_router.core.util.DataExporter
import org.springframework.web.bind.annotation.GetMapping
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
import java.net.URLDecoder
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
import java.lang.StringBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import java.net.InetAddress
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.io.IOException
import java.security.GeneralSecurityException
import java.io.DataOutputStream
import java.io.UnsupportedEncodingException
import java.lang.StringBuffer
import com.comcast.cdn.traffic_control.traffic_router.core.util.StringProtector
import java.util.concurrent.atomic.AtomicInteger
import java.lang.IllegalArgumentException
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
import org.springframework.context.support.FileSystemXmlApplicationContext
import org.apache.catalina.startup.Catalina
import org.apache.catalina.core.StandardService
import org.apache.catalina.core.StandardHost
import org.apache.catalina.core.StandardContext
import java.security.Security
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1KeySpecDecoder
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs8
import java.security.spec.RSAPrivateCrtKeySpec
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1SequenceParser
import org.bouncycastle.asn1.ASN1Integer
import java.security.spec.RSAPublicKeySpec
import com.comcast.cdn.traffic_control.traffic_router.shared.SigningData
import java.security.KeyPairGenerator
import com.comcast.cdn.traffic_control.traffic_router.shared.IsEqualCollection
import javax.management.NotificationBroadcasterSupport
import javax.management.AttributeChangeNotification
import sun.security.rsa.RSAPrivateCrtKeyImpl
import com.comcast.cdn.traffic_control.traffic_router.utils.HttpsProperties
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509KeyManager
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import java.security.Principal
import java.lang.UnsupportedOperationException
import javax.net.ssl.SSLEngine
import javax.net.ssl.ExtendedSSLSession
import com.comcast.cdn.traffic_control.traffic_router.secure.HandshakeData
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDecoder
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataConverter
import kotlin.jvm.Volatile
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterNioEndpoint
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry.CertificateRegistryHolder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import javax.management.NotificationListener
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataListener
import com.comcast.cdn.traffic_control.traffic_router.secure.PrivateKeyDecoder
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey
import org.apache.catalina.LifecycleListener
import org.apache.catalina.LifecycleEvent
import com.comcast.cdn.traffic_control.traffic_router.tomcat.TomcatLifecycleListener
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterProtocolHandler
import com.comcast.cdn.traffic_control.traffic_router.protocol.LanguidPoller
import org.apache.tomcat.util.net.SSLHostConfigCertificate
import org.apache.tomcat.util.net.SSLUtilBase
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterSslUtil
import org.apache.tomcat.util.net.openssl.OpenSSLEngine
import org.apache.tomcat.util.net.openssl.OpenSSLContext
import javax.net.ssl.SSLSessionContext
import org.apache.coyote.http11.Http11NioProtocol
import com.comcast.cdn.traffic_control.traffic_router.protocol.LanguidProtocol
import org.apache.tomcat.util.net.NioEndpoint
import org.apache.tomcat.util.net.SSLHostConfig
import org.apache.tomcat.util.net.SocketWrapperBase
import org.apache.tomcat.util.net.NioChannel
import org.apache.tomcat.util.net.SocketEvent
import org.apache.tomcat.util.net.SocketProcessorBase
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterNioEndpoint.RouterSocketProcessor
import org.apache.tomcat.jni.SSL
import org.apache.coyote.http11.AbstractHttp11JsseProtocol
import com.comcast.cdn.traffic_control.traffic_router.protocol.LanguidNioProtocol
import java.lang.ClassNotFoundException
import org.apache.coyote.ProtocolHandler
import org.apache.tomcat.util.net.SSLImplementation
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.jsse.JSSESupport
import org.apache.tomcat.util.net.SSLUtil
import secure.KeyManagerTest.TestSNIServerName
import java.lang.management.ManagementFactory
import secure.CertificateDataConverterTest
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterSslImplementation
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.hamcrest.Matchers
import org.hamcrest.core.IsEqual
import org.hamcrest.core.IsNot
import org.junit.Assert
import org.junit.Test
import org.junit.experimental.categories.Category
import java.lang.Exception
import java.util.*

@Category(ExternalTest::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SteeringTest {
    var steeringDeliveryServiceId: String? = null
    var targetDomains: MutableMap<String?, String?>? = HashMap()
    var targetWeights: MutableMap<String?, Int?>? = HashMap()
    var httpClient: CloseableHttpClient? = null
    var validLocations: MutableList<String?>? = ArrayList()
    var routerHttpPort = System.getProperty("routerHttpPort", "8888")
    var testHttpPort = System.getProperty("testHttpServerPort", "8889")
    @Throws(IOException::class)
    fun getJsonForResourcePath(resourcePath: String?): JsonNode? {
        val objectMapper = ObjectMapper(JsonFactory())
        val inputStream = javaClass.classLoader.getResourceAsStream(resourcePath)
        if (inputStream == null) {
            Assert.fail("Could not find file '$resourcePath' needed for test from the current classpath as a resource!")
        }
        return objectMapper.readTree(inputStream)["response"][0]
    }

    @Throws(IOException::class)
    fun setupSteering(
        domains: MutableMap<String?, String?>?,
        weights: MutableMap<String?, Int?>?,
        resourcePath: String?
    ): String? {
        domains.clear()
        weights.clear()
        val steeringNode = getJsonForResourcePath(resourcePath)
        val steeredDeliveryServices = steeringNode.get("targets").iterator()
        while (steeredDeliveryServices.hasNext()) {
            val steeredDeliveryService = steeredDeliveryServices.next()
            val targetId = steeredDeliveryService["deliveryService"].asText()
            val targetWeight = steeredDeliveryService["weight"].asInt()
            weights[targetId] = targetWeight
            domains[targetId] = ""
        }
        //System.out.println("steeringNode.get = "+ steeringNode.get("deliveryService").asText());
        return steeringNode.get("deliveryService").asText()
    }

    @Throws(IOException::class)
    fun setupCrConfig() {
        val resourcePath = "publish/CrConfig.json"
        val inputStream = javaClass.classLoader.getResourceAsStream(resourcePath)
        if (inputStream == null) {
            Assert.fail("Could not find file '$resourcePath' needed for test from the current classpath as a resource!")
        }
        val jsonNode = ObjectMapper(JsonFactory()).readTree(inputStream)
        val deliveryServices = jsonNode["deliveryServices"].fieldNames()
        while (deliveryServices.hasNext()) {
            val dsId = deliveryServices.next()
            if (targetDomains.containsKey(dsId)) {
                targetDomains[dsId] = jsonNode["deliveryServices"][dsId]["domains"][0].asText()
            }
        }
        Assert.assertThat(steeringDeliveryServiceId, IsNot.not(Matchers.nullValue()))
        Assert.assertThat(targetDomains.isEmpty(), IsEqual.equalTo(false))
        for (deliveryServiceId in targetDomains.keys) {
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
                    validLocations.add("http://" + cacheId + "." + targetDomains.get(deliveryServiceId) + portText + "/stuff?fakeClientIpAddress=12.34.56.78")
                }
            }
        }
        Assert.assertThat(validLocations.isEmpty(), IsEqual.equalTo(false))
    }

    @Before
    @Throws(Exception::class)
    fun before() {
        steeringDeliveryServiceId = setupSteering(targetDomains, targetWeights, "api/2.0/steering")
        setupCrConfig()
        httpClient = HttpClientBuilder.create().disableRedirectHandling().build()
    }

    @Test
    @Throws(Exception::class)
    fun itUsesSteeredDeliveryServiceIdInRedirect() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/stuff?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "foo.$steeringDeliveryServiceId.bar")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(
                "Failed getting 302 for request " + httpGet.getFirstHeader("Host").value,
                response.statusLine.statusCode,
                IsEqual.equalTo(302)
            )
            Assert.assertThat(response.getFirstHeader("Location").value, Matchers.isIn(validLocations))
            //System.out.println("itUsesSteered = "+response.getFirstHeader("Location").getValue());
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itUsesTargetFiltersForSteering() {
        val httpGet =
            HttpGet("http://localhost:$routerHttpPort/qwerytuiop/force-to-target-2/asdfghjkl?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "foo.steering-test-1.thecdn.example.com")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(
                "Failed getting 302 for request " + httpGet.getFirstHeader("Host").value,
                response.statusLine.statusCode,
                IsEqual.equalTo(302)
            )
            Assert.assertThat(
                response.getFirstHeader("Location").value,
                Matchers.endsWith(".steering-target-2.thecdn.example.com:8090/qwerytuiop/force-to-target-2/asdfghjkl?fakeClientIpAddress=12.34.56.78")
            )
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itUsesXtcSteeringOptionForOverride() {
        val httpGet =
            HttpGet("http://localhost:$routerHttpPort/qwerytuiop/force-to-target-2/asdfghjkl?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "foo.steering-test-1.thecdn.example.com")
        httpGet.addHeader("X-TC-Steering-Option", "steering-target-1")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            Assert.assertThat(
                "Failed getting 302 for request " + httpGet.getFirstHeader("Host").value,
                response.statusLine.statusCode,
                IsEqual.equalTo(302)
            )
            Assert.assertThat(
                response.getFirstHeader("Location").value,
                Matchers.endsWith(".steering-target-1.thecdn.example.com:8090/qwerytuiop/force-to-target-2/asdfghjkl?fakeClientIpAddress=12.34.56.78")
            )
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itReturns503ForBadDeliveryServiceInXtcSteeringOption() {
        val httpGet = HttpGet("http://localhost:$routerHttpPort/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78")
        httpGet.addHeader("Host", "foo.steering-test-1.thecdn.example.com")
        httpGet.addHeader("X-TC-Steering-Option", "ds-02")
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
    fun itUsesWeightedDistributionForRequestPath() {
        var count = 0
        for (weight in targetWeights.values) {
            count += weight
        }
        count *= 1000
        if (count > 100000) {
            count = 100000
        }
        val results: MutableMap<String?, Int?> = HashMap()
        for (steeredId in targetWeights.keys) {
            results[steeredId] = 0
        }

        //System.out.println("Going to execute " + count + " requests through steering delivery service '" + steeringDeliveryServiceId + "'");
        for (i in 0 until count) {
            val path = generateRandomPath()
            val httpGet = HttpGet("http://localhost:$routerHttpPort$path?fakeClientIpAddress=12.34.56.78")
            httpGet.addHeader("Host", "foo.$steeringDeliveryServiceId.bar")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpGet)
                Assert.assertThat(
                    "Did not get 302 for request '" + httpGet.uri + "'",
                    response.statusLine.statusCode,
                    IsEqual.equalTo(302)
                )
                val location = response.getFirstHeader("Location").value
                for (id in results.keys) {
                    if (location.contains(id)) {
                        results[id] = results[id] + 1
                    }
                }
            } finally {
                response?.close()
            }
        }
        var totalWeight = 0.0
        for (weight in targetWeights.values) {
            totalWeight += weight.toDouble()
        }
        val expectedHitRates: MutableMap<String?, Double?> = HashMap()
        for (id in targetWeights.keys) {
            expectedHitRates[id] = targetWeights.get(id) / totalWeight
        }
        for (id in results.keys) {
            val hits: Int = results[id]
            val hitRate = hits as Double / count
            Assert.assertThat(hitRate, IsCloseTo.closeTo(expectedHitRates[id], 0.009))
        }
    }

    @Test
    @Throws(Exception::class)
    fun z_itemsMigrateFromSmallerToLargerBucket() {
        val domains: MutableMap<String?, String?> = HashMap()
        val weights: MutableMap<String?, Int?> = HashMap()
        setupSteering(domains, weights, "api/2.0/steering2")
        val randomPaths: MutableList<String?> = ArrayList()
        for (i in 0..9999) {
            randomPaths.add(generateRandomPath())
        }
        var smallerTarget: String? = null
        var largerTarget: String? = null
        for (target in weights.keys) {
            if (smallerTarget == null && largerTarget == null) {
                smallerTarget = target
                largerTarget = target
            }
            if (weights[smallerTarget] > weights[target]) {
                smallerTarget = target
            }
            if (weights[largerTarget] < weights[target]) {
                largerTarget = target
            }
        }
        val hashedPaths: MutableMap<String?, MutableList<String?>?> = HashMap()
        hashedPaths[smallerTarget] = ArrayList()
        hashedPaths[largerTarget] = ArrayList()
        for (path in randomPaths) {
            val httpGet = HttpGet("http://localhost:$routerHttpPort$path?fakeClientIpAddress=12.34.56.78")
            httpGet.addHeader("Host", "foo.$steeringDeliveryServiceId.bar")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpGet)
                Assert.assertThat(
                    "Did not get 302 for request '" + httpGet.uri + "'",
                    response.statusLine.statusCode,
                    IsEqual.equalTo(302)
                )
                val location = response.getFirstHeader("Location").value
                for (targetXmlId in hashedPaths.keys) {
                    if (location.contains(targetXmlId)) {
                        hashedPaths[targetXmlId].add(path)
                    }
                }
            } finally {
                response?.close()
            }
        }

        // Change the steering attributes
        val httpPost = HttpPost("http://localhost:$testHttpPort/steering")
        httpClient.execute(httpPost).close()

        // a polling interval of 60 seconds is common
        Thread.sleep((90 * 1000).toLong())
        val rehashedPaths: MutableMap<String?, MutableList<String?>?> = HashMap()
        rehashedPaths[smallerTarget] = ArrayList()
        rehashedPaths[largerTarget] = ArrayList()
        for (path in randomPaths) {
            val httpGet = HttpGet("http://localhost:$routerHttpPort$path?fakeClientIpAddress=12.34.56.78")
            httpGet.addHeader("Host", "foo.$steeringDeliveryServiceId.bar")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpGet)
                Assert.assertThat(
                    "Did not get 302 for request '" + httpGet.uri + "'",
                    response.statusLine.statusCode,
                    IsEqual.equalTo(302)
                )
                val location = response.getFirstHeader("Location").value
                for (targetXmlId in rehashedPaths.keys) {
                    if (location.contains(targetXmlId)) {
                        rehashedPaths[targetXmlId].add(path)
                    }
                }
            } finally {
                response?.close()
            }
        }
        Assert.assertThat(
            rehashedPaths[smallerTarget].size, Matchers.greaterThan(
                hashedPaths[smallerTarget].size
            )
        )
        Assert.assertThat(
            rehashedPaths[largerTarget].size, Matchers.lessThan(
                hashedPaths[largerTarget].size
            )
        )
        for (path in hashedPaths[smallerTarget]) {
            Assert.assertThat(rehashedPaths[smallerTarget].contains(path), IsEqual.equalTo(true))
            Assert.assertThat(rehashedPaths[largerTarget].contains(path), IsEqual.equalTo(false))
        }
    }

    var alphanumericCharacters: String? = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWZYZ"
    var exampleValidPathCharacters: String? = "$alphanumericCharacters/=;()-."
    var random: Random? = Random(1462307930227L)
    fun generateRandomPath(): String? {
        val pathLength = 60 + random.nextInt(61)
        val stringBuilder = StringBuilder("/")
        for (i in 0..3) {
            val index = random.nextInt(alphanumericCharacters.length)
            stringBuilder.append(alphanumericCharacters.get(index))
        }
        stringBuilder.append("/")
        for (i in 0 until pathLength) {
            val index = random.nextInt(exampleValidPathCharacters.length)
            stringBuilder.append(exampleValidPathCharacters.get(index))
        }
        return stringBuilder.toString()
    }

    @Test
    @Throws(Exception::class)
    fun itUsesMultiLocationFormatResponse() {
        val paths: MutableList<String?> = ArrayList()
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=true")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=TRUE")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=TruE")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=T")
        for (path in paths) {
            val httpGet = HttpGet("http://localhost:$routerHttpPort$path")
            httpGet.addHeader("Host", "tr.client-steering-test-1.thecdn.example.com")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpGet)
                val location1 = ".client-steering-target-2.thecdn.example.com:8090$path"
                val location2 = ".client-steering-target-1.thecdn.example.com:8090$path"
                Assert.assertThat(
                    "Failed getting 302 for request " + httpGet.getFirstHeader("Host").value,
                    response.statusLine.statusCode,
                    IsEqual.equalTo(302)
                )
                Assert.assertThat(response.getFirstHeader("Location").value, Matchers.endsWith(location1))
                val entity = response.entity
                val objectMapper = ObjectMapper(JsonFactory())
                Assert.assertThat(entity.content, IsNot.not(Matchers.nullValue()))
                val json = objectMapper.readTree(entity.content)
                Assert.assertThat(json.has("locations"), IsEqual.equalTo(true))
                Assert.assertThat(json["locations"].size(), IsEqual.equalTo(2))
                Assert.assertThat(
                    json["locations"][0].asText(),
                    IsEqual.equalTo(response.getFirstHeader("Location").value)
                )
                Assert.assertThat(json["locations"][1].asText(), Matchers.endsWith(location2))
            } finally {
                response?.close()
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun itUsesMultiLocationFormatResponseWithout302() {
        val paths: MutableList<String?> = ArrayList()
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=false")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=FALSE")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=FalsE")
        for (path in paths) {
            val httpGet = HttpGet("http://localhost:$routerHttpPort$path")
            httpGet.addHeader("Host", "tr.client-steering-test-1.thecdn.example.com")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpGet)
                val location1 = ".client-steering-target-2.thecdn.example.com:8090$path"
                val location2 = ".client-steering-target-1.thecdn.example.com:8090$path"
                Assert.assertThat(
                    "Failed getting 200 for request " + httpGet.getFirstHeader("Host").value,
                    response.statusLine.statusCode,
                    IsEqual.equalTo(200)
                )
                val entity = response.entity
                val objectMapper = ObjectMapper(JsonFactory())
                Assert.assertThat(entity.content, IsNot.not(Matchers.nullValue()))
                val json = objectMapper.readTree(entity.content)
                Assert.assertThat(json.has("locations"), IsEqual.equalTo(true))
                Assert.assertThat(json["locations"].size(), IsEqual.equalTo(2))
                Assert.assertThat(json["locations"][0].asText(), Matchers.endsWith(location1))
                Assert.assertThat(json["locations"][1].asText(), Matchers.endsWith(location2))
            } finally {
                response?.close()
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun itUsesNoMultiLocationFormatResponseWithout302WithHead() {
        val paths: MutableList<String?> = ArrayList()
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=false")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=FALSE")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=FalsE")
        for (path in paths) {
            val httpHead = HttpHead("http://localhost:$routerHttpPort$path")
            httpHead.addHeader("Host", "tr.client-steering-test-1.thecdn.example.com")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpHead)
                Assert.assertThat(
                    "Failed getting 200 for request " + httpHead.getFirstHeader("Host").value,
                    response.statusLine.statusCode,
                    IsEqual.equalTo(200)
                )
                Assert.assertThat("Failed getting null body for HEAD request", response.entity, Matchers.nullValue())
            } finally {
                response?.close()
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun itUsesNoMultiLocationFormatResponseWithHead() {
        val paths: MutableList<String?> = ArrayList()
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=true")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=TRUE")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=TruE")
        paths.add("/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78&" + RouterFilter.Companion.REDIRECT_QUERY_PARAM + "=T")
        for (path in paths) {
            val httpHead = HttpHead("http://localhost:$routerHttpPort$path")
            httpHead.addHeader("Host", "tr.client-steering-test-1.thecdn.example.com")
            var response: CloseableHttpResponse? = null
            try {
                response = httpClient.execute(httpHead)
                val location = ".client-steering-target-2.thecdn.example.com:8090$path"
                Assert.assertThat(
                    "Failed getting 302 for request " + httpHead.getFirstHeader("Host").value,
                    response.statusLine.statusCode,
                    IsEqual.equalTo(302)
                )
                Assert.assertThat(response.getFirstHeader("Location").value, Matchers.endsWith(location))
                Assert.assertThat("Failed getting null body for HEAD request", response.entity, Matchers.nullValue())
            } finally {
                response?.close()
            }
        }
    }

    @Test
    @Throws(Exception::class)
    fun itUsesMultiLocationFormatWithMoreThanTwoEntries() {
        val path = "/qwerytuiop/asdfghjkl?fakeClientIpAddress=12.34.56.78"
        val httpGet = HttpGet("http://localhost:$routerHttpPort$path")
        httpGet.addHeader("Host", "tr.client-steering-test-2.thecdn.example.com")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            val location1 = ".steering-target-2.thecdn.example.com:8090$path"
            val location2 = ".steering-target-1.thecdn.example.com:8090$path"
            val location3 = ".client-steering-target-2.thecdn.example.com:8090$path"
            val location4 = ".client-steering-target-4.thecdn.example.com:8090$path"
            val location5 = ".client-steering-target-3.thecdn.example.com:8090$path"
            val location6 = ".client-steering-target-1.thecdn.example.com:8090$path"
            val location7 = ".steering-target-4.thecdn.example.com:8090$path"
            val location8 = ".steering-target-3.thecdn.example.com:8090$path"
            val entity = response.entity
            Assert.assertThat(
                "Failed getting 302 for request " + httpGet.getFirstHeader("Host").value,
                response.statusLine.statusCode,
                IsEqual.equalTo(302)
            )
            Assert.assertThat(response.getFirstHeader("Location").value, Matchers.endsWith(location1))
            val objectMapper = ObjectMapper(JsonFactory())
            Assert.assertThat(entity.content, IsNot.not(Matchers.nullValue()))
            val json = objectMapper.readTree(entity.content)
            Assert.assertThat(json.has("locations"), IsEqual.equalTo(true))
            Assert.assertThat(json["locations"].size(), IsEqual.equalTo(8))
            Assert.assertThat(json["locations"][0].asText(), IsEqual.equalTo(response.getFirstHeader("Location").value))
            Assert.assertThat(json["locations"][1].asText(), Matchers.endsWith(location2))
            Assert.assertThat(json["locations"][2].asText(), Matchers.endsWith(location3))
            Assert.assertThat(json["locations"][3].asText(), Matchers.endsWith(location4))
            Assert.assertThat(json["locations"][4].asText(), Matchers.endsWith(location5))
            Assert.assertThat(json["locations"][5].asText(), Matchers.endsWith(location6))
            Assert.assertThat(json["locations"][6].asText(), Matchers.endsWith(location7))
            Assert.assertThat(json["locations"][7].asText(), Matchers.endsWith(location8))
        } finally {
            response?.close()
        }
    }

    @Test
    @Throws(Exception::class)
    fun itSupportsClientSteeringDiversity() {
        val path = "/foo?fakeClientIpAddress=192.168.42.10" // this IP should get a DEEP_CZ hit (via dczmap.json)
        val httpGet = HttpGet("http://localhost:$routerHttpPort$path")
        httpGet.addHeader("Host", "cdn.client-steering-diversity-test.thecdn.example.com")
        var response: CloseableHttpResponse? = null
        try {
            response = httpClient.execute(httpGet)
            val entity = response.entity
            Assert.assertThat(
                "Failed getting 302 for request " + httpGet.getFirstHeader("Host").value,
                response.statusLine.statusCode,
                IsEqual.equalTo(302)
            )
            val objectMapper = ObjectMapper(JsonFactory())
            Assert.assertThat(entity.content, IsNot.not(Matchers.nullValue()))
            val json = objectMapper.readTree(entity.content)
            Assert.assertThat(json.has("locations"), IsEqual.equalTo(true))
            Assert.assertThat(json["locations"].size(), IsEqual.equalTo(5))
            val actualEdgesList: MutableList<String?> = ArrayList()
            val actualTargets: MutableSet<String?> = HashSet()
            for (n in json["locations"]) {
                var l = n.asText()
                l = l.replaceFirst("http://".toRegex(), "")
                val parts: Array<String?> = l.split("\\.".toRegex()).toTypedArray()
                actualEdgesList.add(parts[0])
                actualTargets.add(parts[1])
            }

            // assert that:
            // - 1st and 2nd targets are edges from the deep cachegroup (because this is a deep hit)
            // - 3rd target is the last unselected edge, which is *not* in the deep cachegroup
            //   (because once all the deep edges have been selected, we select from the regular cachegroup)
            // - 4th and 5th targets are any of the three edges (because all available edges have already been selected)
            val deepEdges: MutableSet<String?> = HashSet()
            deepEdges.add("edge-cache-csd-1")
            deepEdges.add("edge-cache-csd-2")
            val allEdges: MutableSet<String?> = HashSet(deepEdges)
            allEdges.add("edge-cache-csd-3")
            Assert.assertThat(actualEdgesList[0], Matchers.isIn(deepEdges))
            Assert.assertThat(actualEdgesList[1], Matchers.isIn(deepEdges))
            Assert.assertThat(actualEdgesList[2], IsEqual.equalTo("edge-cache-csd-3"))
            Assert.assertThat(actualEdgesList[3], Matchers.isIn(allEdges))
            Assert.assertThat(actualEdgesList[4], Matchers.isIn(allEdges))

            // assert that all 5 steering targets are included in the response
            val expectedTargetsArray =
                arrayOf<String?>("csd-target-1", "csd-target-2", "csd-target-3", "csd-target-4", "csd-target-5")
            val expectedTargets: MutableSet<String?> = HashSet(Arrays.asList(*expectedTargetsArray))
            Assert.assertThat(actualTargets, IsEqual.equalTo(expectedTargets))
        } finally {
            response?.close()
        }
    }
}