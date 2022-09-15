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
package org.apache.traffic_control.traffic_router.core.router

import org.apache.traffic_control.traffic_router.core.ds.DeliveryService
import org.apache.traffic_control.traffic_router.core.ds.Dispersion
import org.apache.traffic_control.traffic_router.core.ds.SteeringRegistry
import org.apache.traffic_control.traffic_router.core.edge.*
import org.apache.traffic_control.traffic_router.core.edge.Cache
import org.apache.traffic_control.traffic_router.core.edge.Node.IPVersions
import org.apache.traffic_control.traffic_router.core.hash.ConsistentHasher
import org.apache.traffic_control.traffic_router.core.loc.FederationRegistry
import org.apache.traffic_control.traffic_router.core.request.DNSRequest
import org.apache.traffic_control.traffic_router.core.request.HTTPRequest
import org.apache.traffic_control.traffic_router.core.request.Request
import org.apache.traffic_control.traffic_router.core.router.HTTPRouteResult
import org.apache.traffic_control.traffic_router.core.router.StatTracker
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.RouteType
import org.apache.traffic_control.traffic_router.core.router.TrafficRouter
import org.apache.traffic_control.traffic_router.core.util.CidrAddress
import org.apache.traffic_control.traffic_router.geolocation.Geolocation
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.*
import org.mockito.ArgumentMatchers
import org.mockito.Mockito
import org.powermock.reflect.Whitebox
import org.xbill.DNS.*
import java.net.*

import org.springframework.web.bind.annotation .RequestMapping
import org.springframework.beans.factory.annotation.Autowired
import org.apache.traffic_control.traffic_router.core.util.DataExporter
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ResponseBody
import java.util.HashMap
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RequestMethod
import org.apache.traffic_control.traffic_router.core.status.model.CacheModel
import org.apache.traffic_control.traffic_router.core.ds.SteeringRegistry
import org.springframework.http.ResponseEntity
import org.apache.traffic_control.traffic_router.core.ds.Steering
import org.apache.traffic_control.traffic_router.core.router.TrafficRouterManager
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
import java.util.SortedMap
import java.util.Collections
import org.apache.traffic_control.traffic_router.core.hash.DefaultHashable
import org.apache.traffic_control.traffic_router.geolocation.Geolocation
import com.fasterxml.jackson.annotation.JsonIgnore
import java.util.HashSet
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService.DeepCachingType
import org.apache.traffic_control.traffic_router.core.util.JsonUtilsException
import kotlin.Throws
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import java.lang.StringBuilder
import org.apache.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import org.apache.traffic_control.traffic_router.core.request.DNSRequest
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService.TransInfoType
import java.io.IOException
import java.security.GeneralSecurityException
import java.io.DataOutputStream
import java.util.Locale
import java.lang.IllegalArgumentException
import java.util.SortedSet
import java.util.TreeSet
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
import java.util.TreeMap
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
import java.util.Calendar
import java.lang.RuntimeException
import org.apache.traffic_control.traffic_router.core.dns.ZoneManager
import org.apache.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import java.util.concurrent.ConcurrentMap
import org.apache.traffic_control.traffic_router.core.dns.RRSIGCacheKey
import org.apache.traffic_control.traffic_router.core.router.StatTracker
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
import java.security.PrivateKey
import java.security.PublicKey
import org.apache.traffic_control.traffic_router.core.dns.RRSetsBuilder
import java.util.OptionalLong
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
import java.util.NoSuchElementException
import org.springframework.web.filter.OncePerRequestFilter
import org.apache.traffic_control.traffic_router.core.http.HTTPAccessRecord
import org.apache.traffic_control.traffic_router.core.http.RouterFilter
import org.apache.traffic_control.traffic_router.core.http.HTTPAccessEventBuilder
import org.apache.traffic_control.traffic_router.core.http.HttpAccessRequestHeaders
import javax.net.ssl.X509TrustManager
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManager
import org.apache.traffic_control.traffic_router.core.util.Fetcher.DefaultTrustManager
import java.lang.NumberFormatException
import org.apache.traffic_control.traffic_router.core.util.FederationExporter
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
import java.util.Enumeration
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
import javax.net.ssl.TrustManagerFactory
import org.apache.traffic_control.traffic_router.core.external.RouterTest.ClientSslSocketFactory
import org.apache.traffic_control.traffic_router.core.external.RouterTest.TestHostnameVerifier
import javax.net.ssl.SSLHandshakeException
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpHead
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLParameters
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
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509KeyManager
import org.apache.traffic_control.traffic_router.secure.CertificateRegistry
import java.security.Principal
import java.lang.UnsupportedOperationException
import javax.net.ssl.SSLEngine
import javax.net.ssl.ExtendedSSLSession
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
import javax.net.ssl.SSLSessionContext
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

class TrafficRouterTest {
    private var consistentHasher: ConsistentHasher? = null
    private var trafficRouter: TrafficRouter? = null
    private var deliveryService: DeliveryService? = null
    private var federationRegistry: FederationRegistry? = null
    @Before
    @Throws(Exception::class)
    fun before() {
        deliveryService = Mockito.mock(DeliveryService::class.java)
        Mockito.`when`(deliveryService.isAvailable()).thenReturn(true)
        Mockito.`when`(deliveryService.isCoverageZoneOnly()).thenReturn(false)
        Mockito.`when`(deliveryService.getDispersion()).thenReturn(Mockito.mock(Dispersion::class.java))
        Mockito.`when`(deliveryService.isAcceptHttp()).thenReturn(true)
        Mockito.`when`(deliveryService.getId()).thenReturn("someDsName")
        consistentHasher = Mockito.mock(ConsistentHasher::class.java)
        Mockito.`when`(deliveryService.createURIString(ArgumentMatchers.any(HTTPRequest::class.java), ArgumentMatchers.any())).thenReturn("http://atscache.kabletown.net/index.html")
        val inetRecords: MutableList<InetRecord?> = ArrayList()
        val inetRecord = InetRecord("cname1", 12345)
        inetRecords.add(inetRecord)
        federationRegistry = Mockito.mock(FederationRegistry::class.java)
        Mockito.`when`(federationRegistry.findInetRecords(ArgumentMatchers.any(), ArgumentMatchers.any(CidrAddress::class.java))).thenReturn(inetRecords)
        trafficRouter = Mockito.mock(TrafficRouter::class.java)
        val cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(cacheRegister.getDeliveryService(ArgumentMatchers.any(HTTPRequest::class.java))).thenReturn(deliveryService)
        Whitebox.setInternalState(trafficRouter, "cacheRegister", cacheRegister)
        Whitebox.setInternalState(trafficRouter, "federationRegistry", federationRegistry)
        Whitebox.setInternalState(trafficRouter, "consistentHasher", consistentHasher)
        Whitebox.setInternalState(trafficRouter, "steeringRegistry", Mockito.mock(SteeringRegistry::class.java))
        Mockito.`when`(trafficRouter.route(ArgumentMatchers.any(DNSRequest::class.java), ArgumentMatchers.any(StatTracker.Track::class.java))).thenCallRealMethod()
        Mockito.`when`(trafficRouter.route(ArgumentMatchers.any(HTTPRequest::class.java), ArgumentMatchers.any(StatTracker.Track::class.java))).thenCallRealMethod()
        Mockito.`when`(trafficRouter.singleRoute(ArgumentMatchers.any(HTTPRequest::class.java), ArgumentMatchers.any(StatTracker.Track::class.java))).thenCallRealMethod()
        Mockito.`when`(trafficRouter.selectDeliveryService(ArgumentMatchers.any(Request::class.java))).thenReturn(deliveryService)
        Mockito.`when`(trafficRouter.consistentHashDeliveryService(ArgumentMatchers.any(DeliveryService::class.java), ArgumentMatchers.any(HTTPRequest::class.java), ArgumentMatchers.any())).thenCallRealMethod()
        Mockito.doCallRealMethod().`when`(trafficRouter).stripSpecialQueryParams(ArgumentMatchers.any(HTTPRouteResult::class.java))
    }

    @Test
    @Throws(Exception::class)
    fun itCreatesDnsResultsFromFederationMappingHit() {
        val name = Name.fromString("edge.example.com")
        val request = DNSRequest("example.com", name, Type.A)
        request.clientIP = "192.168.10.11"
        request.hostname = name.relativize(Name.root).toString()
        val track = Mockito.spy<StatTracker.Track?>(StatTracker.Companion.getTrack())
        Mockito.`when`(deliveryService.getRoutingName()).thenReturn("edge")
        Mockito.`when`(deliveryService.isDns()).thenReturn(true)
        val result = trafficRouter.route(request, track)
        MatcherAssert.assertThat(result.addresses, Matchers.containsInAnyOrder(InetRecord("cname1", 12345)))
        Mockito.verify(track).setRouteType(RouteType.DNS, "edge.example.com")
    }

    @Test
    @Throws(Exception::class)
    fun itCreatesHttpResults() {
        val httpRequest = HTTPRequest()
        httpRequest.clientIP = "192.168.10.11"
        httpRequest.hostname = "ccr.example.com"
        val headers: MutableMap<String?, String?> = HashMap()
        headers["x-tc-steering-option"] = "itCreatesHttpResults"
        httpRequest.headers = headers
        val track = Mockito.spy<StatTracker.Track?>(StatTracker.Companion.getTrack())
        val cache = Mockito.mock(Cache::class.java)
        Mockito.`when`(cache.hasDeliveryService(ArgumentMatchers.anyString())).thenReturn(true)
        val cacheLocation = CacheLocation("", Geolocation(50.0, 50.0))
        cacheLocation.addCache(cache)
        val cacheLocationCollection: MutableSet<CacheLocation?> = HashSet()
        cacheLocationCollection.add(cacheLocation)
        val cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(cacheRegister.cacheLocations).thenReturn(cacheLocationCollection)
        Mockito.`when`<MutableList<*>?>(deliveryService.filterAvailableLocations(ArgumentMatchers.any(MutableCollection::class.java))).thenCallRealMethod()
        Mockito.`when`(deliveryService.isLocationAvailable(cacheLocation)).thenReturn(true)
        val caches: MutableList<Cache?> = ArrayList()
        caches.add(cache)
        Mockito.`when`(trafficRouter.selectCaches(ArgumentMatchers.any(HTTPRequest::class.java), ArgumentMatchers.any(DeliveryService::class.java), ArgumentMatchers.any(StatTracker.Track::class.java))).thenReturn(caches)
        Mockito.`when`(trafficRouter.selectCachesByGeo(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.getClientLocation(ArgumentMatchers.anyString(), ArgumentMatchers.any(DeliveryService::class.java), ArgumentMatchers.any(CacheLocation::class.java), ArgumentMatchers.any(StatTracker.Track::class.java))).thenReturn(Geolocation(40.0, -100.0))
        Mockito.`when`(trafficRouter.getCachesByGeo(ArgumentMatchers.any(DeliveryService::class.java), ArgumentMatchers.any(Geolocation::class.java), ArgumentMatchers.any(StatTracker.Track::class.java), ArgumentMatchers.any(IPVersions::class.java))).thenCallRealMethod()
        Mockito.`when`(trafficRouter.getCacheRegister()).thenReturn(cacheRegister)
        Mockito.`when`<MutableList<*>?>(trafficRouter.orderLocations(ArgumentMatchers.any(MutableList::class.java), ArgumentMatchers.any(Geolocation::class.java))).thenCallRealMethod()
        val httpRouteResult = trafficRouter.route(httpRequest, track)
        MatcherAssert.assertThat(httpRouteResult.url.toString(), Matchers.equalTo("http://atscache.kabletown.net/index.html"))
    }

    @Test
    @Throws(Exception::class)
    fun itFiltersByIPAvailability() {
        val ds = Mockito.mock(DeliveryService::class.java)
        Mockito.`when`(ds.id).thenReturn("itFiltersByIpAvailable")
        val cacheIPv4 = Mockito.mock(Cache::class.java)
        Mockito.`when`(cacheIPv4.hasDeliveryService(ArgumentMatchers.any())).thenReturn(true)
        Mockito.`when`(cacheIPv4.hasAuthority()).thenReturn(true)
        Mockito.`when`(cacheIPv4.isAvailable(ArgumentMatchers.any(IPVersions::class.java))).thenCallRealMethod()
        Mockito.doCallRealMethod().`when`(cacheIPv4).setIsAvailable(ArgumentMatchers.anyBoolean())
        Whitebox.setInternalState(cacheIPv4, "ipv4Available", true)
        Whitebox.setInternalState(cacheIPv4, "ipv6Available", false)
        cacheIPv4.setIsAvailable(true)
        Mockito.`when`(cacheIPv4.id).thenReturn("cache IPv4")
        val cacheIPv6 = Mockito.mock(Cache::class.java)
        Mockito.`when`(cacheIPv6.hasDeliveryService(ArgumentMatchers.any())).thenReturn(true)
        Mockito.`when`(cacheIPv6.hasAuthority()).thenReturn(true)
        Mockito.`when`(cacheIPv6.isAvailable(ArgumentMatchers.any(IPVersions::class.java))).thenCallRealMethod()
        Mockito.doCallRealMethod().`when`(cacheIPv6).setIsAvailable(ArgumentMatchers.anyBoolean())
        Whitebox.setInternalState(cacheIPv6, "ipv4Available", false)
        Whitebox.setInternalState(cacheIPv6, "ipv6Available", true)
        cacheIPv6.setIsAvailable(true)
        Mockito.`when`(cacheIPv6.id).thenReturn("cache IPv6")
        val caches: MutableList<Cache?> = ArrayList()
        caches.add(cacheIPv4)
        caches.add(cacheIPv6)
        Mockito.`when`(trafficRouter.getSupportingCaches(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        val supportingIPv4Caches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.IPV4ONLY)
        MatcherAssert.assertThat(supportingIPv4Caches.size, Matchers.equalTo(1))
        MatcherAssert.assertThat(supportingIPv4Caches[0].id, Matchers.equalTo("cache IPv4"))
        val supportingIPv6Caches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.IPV6ONLY)
        MatcherAssert.assertThat(supportingIPv6Caches.size, Matchers.equalTo(1))
        MatcherAssert.assertThat(supportingIPv6Caches[0].id, Matchers.equalTo("cache IPv6"))
        val supportingEitherCaches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.ANY)
        MatcherAssert.assertThat(supportingEitherCaches.size, Matchers.equalTo(2))
        cacheIPv6.setIsAvailable(false)
        val supportingAvailableCaches = trafficRouter.getSupportingCaches(caches, ds, IPVersions.ANY)
        MatcherAssert.assertThat(supportingAvailableCaches.size, Matchers.equalTo(1))
        MatcherAssert.assertThat(supportingAvailableCaches[0].id, Matchers.equalTo("cache IPv4"))
    }

    @Test
    @Throws(Exception::class)
    fun itChecksDefaultLocation() {
        val ip = "1.2.3.4"
        val track = StatTracker.Track()
        val geolocation = Mockito.mock(Geolocation::class.java)
        Mockito.`when`(trafficRouter.getClientLocation(ip, deliveryService, null, track)).thenReturn(geolocation)
        Mockito.`when`(geolocation.isDefaultLocation).thenReturn(true)
        Mockito.`when`(geolocation.countryCode).thenReturn("US")
        val map: MutableMap<String?, Geolocation?> = HashMap()
        val defaultUSLocation = Geolocation(37.751, -97.822)
        defaultUSLocation.countryCode = "US"
        map["US"] = defaultUSLocation
        Mockito.`when`(trafficRouter.getDefaultGeoLocationsOverride()).thenReturn(map)
        val cache = Mockito.mock(Cache::class.java)
        val list: MutableList<Cache?> = ArrayList()
        list.add(cache)
        Mockito.`when`(deliveryService.getMissLocation()).thenReturn(defaultUSLocation)
        Mockito.`when`(trafficRouter.getCachesByGeo(deliveryService, deliveryService.getMissLocation(), track, IPVersions.IPV4ONLY)).thenReturn(list)
        Mockito.`when`(trafficRouter.selectCachesByGeo(ip, deliveryService, null, track, IPVersions.IPV4ONLY)).thenCallRealMethod()
        Mockito.`when`(trafficRouter.isValidMissLocation(deliveryService)).thenCallRealMethod()
        val result = trafficRouter.selectCachesByGeo(ip, deliveryService, null, track, IPVersions.IPV4ONLY)
        Mockito.verify(trafficRouter).getCachesByGeo(deliveryService, deliveryService.getMissLocation(), track, IPVersions.IPV4ONLY)
        MatcherAssert.assertThat(result.size, Matchers.equalTo(1))
        MatcherAssert.assertThat(result[0], Matchers.equalTo(cache))
        MatcherAssert.assertThat(track.result, Matchers.equalTo(ResultType.GEO_DS))
    }

    @Test
    @Throws(Exception::class)
    fun itChecksMissLocation() {
        var defaultUSLocation = Geolocation(37.751, -97.822)
        Mockito.`when`(deliveryService.getMissLocation()).thenReturn(defaultUSLocation)
        Mockito.`when`(trafficRouter.isValidMissLocation(deliveryService)).thenCallRealMethod()
        var result = trafficRouter.isValidMissLocation(deliveryService)
        MatcherAssert.assertThat(result, Matchers.equalTo(true))
        defaultUSLocation = Geolocation(0.0, 0.0)
        Mockito.`when`(deliveryService.getMissLocation()).thenReturn(defaultUSLocation)
        result = trafficRouter.isValidMissLocation(deliveryService)
        MatcherAssert.assertThat(result, Matchers.equalTo(false))
    }

    @Test
    @Throws(Exception::class)
    fun itSetsResultToGeo() {
        val cache = Mockito.mock(Cache::class.java)
        Mockito.`when`(cache.hasDeliveryService(ArgumentMatchers.any())).thenReturn(true)
        val cacheLocation = CacheLocation("", Geolocation(50.0, 50.0))
        cacheLocation.addCache(cache)
        val cacheLocationCollection: MutableSet<CacheLocation?> = HashSet()
        cacheLocationCollection.add(cacheLocation)
        val cacheRegister = Mockito.mock(CacheRegister::class.java)
        Mockito.`when`(cacheRegister.cacheLocations).thenReturn(cacheLocationCollection)
        Mockito.`when`(trafficRouter.getCacheRegister()).thenReturn(cacheRegister)
        Mockito.`when`(deliveryService.isLocationAvailable(cacheLocation)).thenReturn(true)
        Mockito.`when`(deliveryService.filterAvailableLocations(ArgumentMatchers.any())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.selectCaches(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any<StatTracker.Track?>())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.selectCaches(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.anyBoolean())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.selectCachesByGeo(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        val clientLocation = Geolocation(40.0, -100.0)
        Mockito.`when`(trafficRouter.getClientLocation(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any())).thenReturn(clientLocation)
        Mockito.`when`(trafficRouter.getCachesByGeo(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.filterEnabledLocations(ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.orderLocations(ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        Mockito.`when`(trafficRouter.getSupportingCaches(ArgumentMatchers.any(), ArgumentMatchers.any(), ArgumentMatchers.any())).thenCallRealMethod()
        val httpRequest = HTTPRequest()
        httpRequest.clientIP = "192.168.10.11"
        httpRequest.hostname = "ccr.example.com"
        httpRequest.path = "/some/path"
        val headers: MutableMap<String?, String?> = HashMap()
        headers["x-tc-steering-option"] = "itSetsResultToGeo"
        httpRequest.headers = headers
        var track = Mockito.spy<StatTracker.Track?>(StatTracker.Companion.getTrack())
        trafficRouter.route(httpRequest, track)
        MatcherAssert.assertThat(track.result, Matchers.equalTo(ResultType.GEO))
        MatcherAssert.assertThat(track.resultLocation, Matchers.equalTo(Geolocation(50.0, 50.0)))
        Mockito.`when`(federationRegistry.findInetRecords(ArgumentMatchers.any(), ArgumentMatchers.any(CidrAddress::class.java))).thenReturn(null)
        Mockito.`when`(deliveryService.getRoutingName()).thenReturn("edge")
        Mockito.`when`(deliveryService.isDns()).thenReturn(true)
        val name = Name.fromString("edge.example.com")
        val dnsRequest = DNSRequest("example.com", name, Type.A)
        dnsRequest.clientIP = "10.10.10.10"
        dnsRequest.hostname = name.relativize(Name.root).toString()
        track = StatTracker.Companion.getTrack()
        trafficRouter.route(dnsRequest, track)
        MatcherAssert.assertThat(track.result, Matchers.equalTo(ResultType.GEO))
        MatcherAssert.assertThat(track.resultLocation, Matchers.equalTo(Geolocation(50.0, 50.0)))
    }

    @Test
    @Throws(Exception::class)
    fun itRetainsPathElementsInURI() {
        val cache = Mockito.mock(Cache::class.java)
        Mockito.`when`(cache.fqdn).thenReturn("atscache-01.kabletown.net")
        Mockito.`when`(cache.port).thenReturn(80)
        Mockito.`when`(deliveryService.createURIString(ArgumentMatchers.any(HTTPRequest::class.java), ArgumentMatchers.any(Cache::class.java))).thenCallRealMethod()
        val httpRequest = HTTPRequest()
        httpRequest.clientIP = "192.168.10.11"
        httpRequest.hostname = "tr.ds.kabletown.net"
        httpRequest.path = "/782-93d215fcd88b/6b6ce2889-ae4c20a1584.ism/manifest(format=m3u8-aapl).m3u8"
        httpRequest.uri = "/782-93d215fcd88b/6b6ce2889-ae4c20a1584.ism;urlsig=O0U9MTQ1Ojhx74tjchm8yzfdanshdafHMNhv8vNA/manifest(format=m3u8-aapl).m3u8"
        val dest = StringBuilder()
        dest.append("http://")
        dest.append(cache.fqdn.split("\\.".toRegex(), limit = 2).toTypedArray()[0])
        dest.append(".")
        dest.append(httpRequest.hostname.split("\\.".toRegex(), limit = 2).toTypedArray()[1])
        dest.append(httpRequest.uri)
        MatcherAssert.assertThat(deliveryService.createURIString(httpRequest, cache), Matchers.equalTo(dest.toString()))
    }

    @Test
    @Throws(MalformedURLException::class)
    fun itStripsSpecialQueryParameters() {
        val result = HTTPRouteResult(false)
        result.url = URL("http://example.org/foo?trred=false&fakeClientIpAddress=192.168.0.2")
        trafficRouter.stripSpecialQueryParams(result)
        MatcherAssert.assertThat(result.url.toString(), Matchers.equalTo("http://example.org/foo"))
        result.url = URL("http://example.org/foo?b=1&trred=false&a=2&asdf=foo&fakeClientIpAddress=192.168.0.2&c=3")
        trafficRouter.stripSpecialQueryParams(result)
        MatcherAssert.assertThat(result.url.toString(), Matchers.equalTo("http://example.org/foo?b=1&a=2&asdf=foo&c=3"))
    }
}