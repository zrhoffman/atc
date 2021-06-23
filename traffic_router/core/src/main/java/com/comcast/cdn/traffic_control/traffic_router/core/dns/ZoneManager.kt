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
package com.comcast.cdn.traffic_control.traffic_router.core.dnsimport

import com.comcast.cdn.traffic_control.traffic_router.core.edge.Resolver
import com.fasterxml.jackson.databind.JsonNode
import com.google.common.cache.CacheStats
import com.google.common.cache.LoadingCache
import com.google.common.cache.RemovalListener
import com.google.common.util.concurrent.ListenableFuture
import com.google.common.util.concurrent.ListenableFutureTask
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Type
import org.xbill.DNS.Zone
import java.io.File
import java.lang.Exception
import java.net.UnknownHostException
import java.time.Duration
import java.util.ArrayList
import java.util.concurrent.Future
import java.util.function.Function

org.springframework.web.bind.annotation .RequestMapping
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

class ZoneManager(
    tr: TrafficRouter?,
    statTracker: StatTracker?,
    trafficOpsUtils: TrafficOpsUtils?,
    trafficRouterManager: TrafficRouterManager?
) : Resolver() {
    private val trafficRouter: TrafficRouter?
    private val statTracker: StatTracker?

    enum class ZoneCacheType {
        DYNAMIC, STATIC
    }

    fun rebuildZoneCache() {
        ZoneManager.Companion.initZoneCache(trafficRouter)
    }

    private fun initSignatureManager(
        cacheRegister: CacheRegister?,
        trafficOpsUtils: TrafficOpsUtils?,
        trafficRouterManager: TrafficRouterManager?
    ) {
        val sm = SignatureManager(this, cacheRegister, trafficOpsUtils, trafficRouterManager)
        ZoneManager.Companion.signatureManager = sm
    }

    fun getStatTracker(): StatTracker? {
        return statTracker
    }

    /**
     * Gets trafficRouter.
     *
     * @return the trafficRouter
     */
    fun getTrafficRouter(): TrafficRouter? {
        return trafficRouter
    }

    /**
     * Attempts to find a [Zone] that would contain the specified [Name].
     *
     * @param name
     * the Name to use to attempt to find the Zone
     * @return the Zone to use to resolve the specified Name
     */
    fun getZone(name: Name?): Zone? {
        return getZone(name, 0)
    }

    /**
     * Attempts to find a [Zone] that would contain the specified [Name].
     *
     * @param name
     * the Name to use to attempt to find the Zone
     * @param qtype
     * the Type to use to control Zone ordering
     * @return the Zone to use to resolve the specified Name
     */
    fun getZone(name: Name?, qtype: Int): Zone? {
        val zoneMap: MutableMap<ZoneKey?, Zone?> = ZoneManager.Companion.zoneCache.asMap()
        val sorted: MutableList<ZoneKey?> = ArrayList(zoneMap.keys)
        var result: Zone? = null
        var target = name
        Collections.sort(sorted)
        if (qtype == Type.DS) {
            target = Name(name, 1) // DS records are in the parent zone, change target accordingly
        }
        for (key in sorted) {
            val zone = zoneMap[key]
            val origin = zone.getOrigin()
            if (target.subdomain(origin)) {
                result = zone
                break
            }
        }
        return result
    }

    /**
     * Creates a dynamic zone that serves a set of A and AAAA records for the specified [Name]
     * .
     *
     * @param staticZone
     * The Zone that would normally serve this request
     * @param builder
     * DNSAccessRecord.Builder access logging
     * @param request
     * DNSRequest representing the query
     * @return the new Zone to serve the request or null if the static Zone should be used
     */
    private fun createDynamicZone(staticZone: Zone?, builder: DNSAccessRecord.Builder?, request: DNSRequest?): Zone? {
        val track: StatTracker.Track = StatTracker.Companion.getTrack()
        try {
            val result = trafficRouter.route(request, track)
            return if (result != null) {
                val dynamicZone: Zone = ZoneManager.Companion.fillDynamicZone(
                    ZoneManager.Companion.dynamicZoneCache,
                    staticZone,
                    request,
                    result
                )
                track.setResultCode(dynamicZone, request.getName(), request.getQueryType())
                dynamicZone
            } else {
                null
            }
        } catch (e: Exception) {
            ZoneManager.Companion.LOGGER.error(e.message, e)
        } finally {
            builder.resultType(track.result)
            builder.resultDetails(track.resultDetails)
            builder.resultLocation(track.resultLocation)
            statTracker.saveTrack(track)
        }
        return null
    }

    private fun lookup(qname: Name?, zone: Zone?, type: Int): MutableList<InetRecord?>? {
        val ipAddresses: MutableList<InetRecord?> = ArrayList()
        val sr = zone.findRecords(qname, type)
        if (sr.isSuccessful) {
            val answers = sr.answers()
            for (answer in answers) {
                val it: MutableIterator<Record?>? = answer.rrs()
                while (it.hasNext()) {
                    val r = it.next()
                    if (r is ARecord) {
                        val ar = r as ARecord?
                        ipAddresses.add(InetRecord(ar.getAddress(), ar.getTTL()))
                    } else if (r is AAAARecord) {
                        val ar = r as AAAARecord?
                        ipAddresses.add(InetRecord(ar.getAddress(), ar.getTTL()))
                    }
                }
            }
            return ipAddresses
        }
        return null
    }

    override fun resolve(fqdn: String?): MutableList<InetRecord?>? {
        try {
            val name = Name(fqdn)
            val zone = getZone(name)
            if (zone == null) {
                ZoneManager.Companion.LOGGER.error("No zone - Defaulting to system resolver: $fqdn")
                return super.resolve(fqdn)
            }
            return lookup(name, zone, Type.A)
        } catch (e: TextParseException) {
            ZoneManager.Companion.LOGGER.warn("TextParseException from: $fqdn", e)
        }
        return null
    }

    @Throws(UnknownHostException::class)
    fun resolve(fqdn: String?, address: String?, builder: DNSAccessRecord.Builder?): MutableList<InetRecord?>? {
        try {
            val name = Name(fqdn)
            var zone = getZone(name)
            val addr = InetAddress.getByName(address)
            val qtype = if (addr is Inet6Address) Type.AAAA else Type.A
            val request = DNSRequest(zone, name, qtype)
            request.clientIP = addr.hostAddress
            request.hostname = name.relativize(Name.root).toString()
            request.isDnssec = true
            val dynamicZone = createDynamicZone(zone, builder, request)
            if (dynamicZone != null) {
                zone = dynamicZone
            }
            if (zone == null) {
                ZoneManager.Companion.LOGGER.error("No zone - Defaulting to system resolver: $fqdn")
                return super.resolve(fqdn)
            }
            return lookup(name, zone, Type.A)
        } catch (e: TextParseException) {
            ZoneManager.Companion.LOGGER.error("TextParseException from: $fqdn")
        }
        return null
    }

    fun getZone(
        qname: Name?,
        qtype: Int,
        clientAddress: InetAddress?,
        isDnssecRequest: Boolean,
        builder: DNSAccessRecord.Builder?
    ): Zone? {
        val zone = getZone(qname, qtype) ?: return null

        // all queries must be dynamic when edge DNS routing is enabled, as NS RRsets are used for the authority section and must be localized
        if (!trafficRouter.isEdgeDNSRouting()) {
            val sr = zone.findRecords(qname, qtype)
            if (sr.isSuccessful) {
                return zone
            }
        }
        val request = DNSRequest(zone, qname, qtype)
        request.clientIP = clientAddress.getHostAddress()
        request.hostname = qname.relativize(Name.root).toString()
        request.isDnssec = isDnssecRequest
        val dynamicZone = createDynamicZone(zone, builder, request)
        return dynamicZone ?: zone
    }

    fun getStaticCacheStats(): CacheStats? {
        return ZoneManager.Companion.zoneCache.stats()
    }

    fun getDynamicCacheStats(): CacheStats? {
        return ZoneManager.Companion.dynamicZoneCache.stats()
    }

    companion object {
        private val LOGGER = Logger.getLogger(ZoneManager::class.java)
        private val dynamicZoneCache: LoadingCache<ZoneKey?, Zone?>? = null
        private val zoneCache: LoadingCache<ZoneKey?, Zone?>? = null
        private val domainsToZoneKeys: ConcurrentMap<String?, ZoneKey?>? = ConcurrentHashMap()
        private val zoneMaintenanceExecutor: ScheduledExecutorService? = null
        private val zoneExecutor: ExecutorService? = null
        private const val DEFAULT_PRIMER_LIMIT = 500
        private val IP: String? = "ip"
        private val IP6: String? = "ip6"
        private val zoneDirectory: File? = null
        private val signatureManager: SignatureManager? = null
        private val topLevelDomain: Name? = null
        private val AAAA: String? = "AAAA"
        fun destroy() {
            ZoneManager.Companion.zoneMaintenanceExecutor.shutdownNow()
            ZoneManager.Companion.zoneExecutor.shutdownNow()
            ZoneManager.Companion.signatureManager.destroy()
        }

        @Throws(TextParseException::class)
        private fun initTopLevelDomain(data: CacheRegister?) {
            var tld: String = optString(data.getConfig(), "domain_name")
            if (!tld.endsWith(".")) {
                tld = "$tld."
            }
            ZoneManager.Companion.setTopLevelDomain(Name(tld))
        }

        protected fun initZoneCache(tr: TrafficRouter?) {
            synchronized(ZoneManager::class.java) {
                val cacheRegister = tr.getCacheRegister()
                val config = cacheRegister.config
                val poolSize: Int = ZoneManager.Companion.calcThreadPoolSize(config)
                val initExecutor = Executors.newFixedThreadPool(poolSize)
                val generationTasks: MutableList<Runnable?> = ArrayList()
                val primingTasks: BlockingQueue<Runnable?> = LinkedBlockingQueue()
                val ze = Executors.newFixedThreadPool(poolSize)
                val me =
                    Executors.newScheduledThreadPool(2) // 2 threads, one for static, one for dynamic, threads to refresh zones
                val maintenanceInterval =
                    JsonUtils.optInt(config, "zonemanager.cache.maintenance.interval", 300) // default 5 minutes
                val initTimeout = JsonUtils.optInt(config, "zonemanager.init.timeout", 10)
                val dzc: LoadingCache<ZoneKey?, Zone?> = ZoneManager.Companion.createZoneCache(
                    ZoneCacheType.DYNAMIC,
                    ZoneManager.Companion.getDynamicZoneCacheSpec(config, poolSize)
                )
                val zc = createZoneCache(ZoneCacheType.STATIC)
                val newDomainsToZoneKeys: ConcurrentMap<String?, ZoneKey?> = ConcurrentHashMap()
                if (tr.isDnssecZoneDiffingEnabled()) {
                    if (ZoneManager.Companion.dynamicZoneCache == null || ZoneManager.Companion.zoneCache == null) {
                        ZoneManager.Companion.initZoneDirectory()
                    } else {
                        ZoneManager.Companion.copyExistingDynamicZones(tr, dzc)
                    }
                } else {
                    ZoneManager.Companion.initZoneDirectory()
                }
                try {
                    ZoneManager.Companion.LOGGER.info("Generating zone data")
                    ZoneManager.Companion.generateZones(
                        tr,
                        zc,
                        dzc,
                        generationTasks,
                        primingTasks,
                        newDomainsToZoneKeys
                    )
                    initExecutor.invokeAll(generationTasks.stream().map { task: Runnable? -> Executors.callable(task) }
                        .collect(Collectors.toList()))
                    ZoneManager.Companion.LOGGER.info("Zone generation complete")
                    val primingStart = Instant.now()
                    val futures =
                        initExecutor.invokeAll(primingTasks.stream().map { task: Runnable? -> Executors.callable(task) }
                            .collect(Collectors.toList()), initTimeout.toLong(), TimeUnit.MINUTES)
                    val primingEnd = Instant.now()
                    if (futures.stream().anyMatch { obj: Future<Any?>? -> obj.isCancelled() }) {
                        ZoneManager.Companion.LOGGER.warn(
                            String.format(
                                "Priming zone cache exceeded time limit of %d minute(s); continuing",
                                initTimeout
                            )
                        )
                    } else {
                        ZoneManager.Companion.LOGGER.info(
                            String.format(
                                "Priming zone cache completed in %s",
                                Duration.between(primingStart, primingEnd).toString()
                            )
                        )
                    }
                    me.scheduleWithFixedDelay(
                        ZoneManager.Companion.getMaintenanceRunnable(
                            dzc,
                            ZoneCacheType.DYNAMIC,
                            maintenanceInterval
                        ), 0, maintenanceInterval.toLong(), TimeUnit.SECONDS
                    )
                    me.scheduleWithFixedDelay(
                        ZoneManager.Companion.getMaintenanceRunnable(
                            zc,
                            ZoneCacheType.STATIC,
                            maintenanceInterval
                        ), 0, maintenanceInterval.toLong(), TimeUnit.SECONDS
                    )
                    val tze: ExecutorService = ZoneManager.Companion.zoneExecutor
                    val tme: ScheduledExecutorService = ZoneManager.Companion.zoneMaintenanceExecutor
                    val tzc: LoadingCache<ZoneKey?, Zone?> = ZoneManager.Companion.zoneCache
                    val tdzc: LoadingCache<ZoneKey?, Zone?> = ZoneManager.Companion.dynamicZoneCache
                    ZoneManager.Companion.zoneExecutor = ze
                    ZoneManager.Companion.zoneMaintenanceExecutor = me
                    ZoneManager.Companion.dynamicZoneCache = dzc
                    ZoneManager.Companion.zoneCache = zc
                    val oldZCSize = tzc?.size() ?: 0
                    val oldDCZSize = if (tzc == null) 0 else tdzc.size()
                    ZoneManager.Companion.LOGGER.info(
                        "old static zone cache size: " + oldZCSize + ", new static zone cache size: " + zc.size() +
                                ", old dynamic zone cache size: " + oldDCZSize + ", new dynamic zone cache size: " + dzc.size()
                    )
                    ZoneManager.Companion.domainsToZoneKeys = newDomainsToZoneKeys
                    if (tze != null) {
                        tze.shutdownNow()
                    }
                    if (tme != null) {
                        tme.shutdownNow()
                    }
                    if (tzc != null) {
                        tzc.invalidateAll()
                    }
                    if (tdzc != null) {
                        tdzc.invalidateAll()
                    }
                    ZoneManager.Companion.LOGGER.info("Initialization of zone data completed")
                } catch (ex: InterruptedException) {
                    ZoneManager.Companion.LOGGER.warn(
                        String.format(
                            "Initialization of zone data was interrupted, timeout of %d minute(s); continuing",
                            initTimeout
                        ), ex
                    )
                } catch (ex: IOException) {
                    ZoneManager.Companion.LOGGER.fatal("Caught fatal exception while generating zone data!", ex)
                }
            }
        }

        private fun copyExistingDynamicZones(tr: TrafficRouter?, dzc: LoadingCache<ZoneKey?, Zone?>?) {
            val allZones: MutableMap<String?, DeliveryService?> = ZoneManager.Companion.getAllDeliveryServiceDomains(tr)
            allZones[ZoneManager.Companion.getTopLevelDomain().toString(true)] = null
            val dzcMap: MutableMap<ZoneKey?, Zone?> = ZoneManager.Companion.dynamicZoneCache.asMap()
            for (zoneKey in dzcMap.keys) {
                if (allZones.containsKey(zoneKey.getName().toString(true))) {
                    dzc.put(zoneKey, dzcMap[zoneKey])
                } else {
                    ZoneManager.Companion.LOGGER.info(
                        "domain for old zone " + zoneKey.getName()
                            .toString(true) + " not found; will not copy it into new dynamic zone cache"
                    )
                }
            }
        }

        private fun calcThreadPoolSize(config: JsonNode?): Int {
            var poolSize = 1
            val scale = JsonUtils.optDouble(config, "zonemanager.threadpool.scale", 0.75)
            val cores = Runtime.getRuntime().availableProcessors()
            if (cores > 2) {
                val s = Math.floor(cores as Double * scale)
                if (s.toInt() > 1) {
                    poolSize = s.toInt()
                }
            }
            return poolSize
        }

        private fun getDynamicZoneCacheSpec(config: JsonNode?, poolSize: Int): CacheBuilderSpec? {
            val cacheSpec: MutableList<String?> = ArrayList()
            cacheSpec.add(
                "expireAfterAccess=" + JsonUtils.optString(
                    config,
                    "zonemanager.dynamic.response.expiration",
                    "3600s"
                )
            ) // default to one hour
            cacheSpec.add(
                "concurrencyLevel=" + JsonUtils.optString(
                    config,
                    "zonemanager.dynamic.concurrencylevel",
                    poolSize.toString()
                )
            ) // default to pool size, 4 is the actual default
            cacheSpec.add(
                "initialCapacity=" + JsonUtils.optInt(
                    config,
                    "zonemanager.dynamic.initialcapacity",
                    10000
                )
            ) // set the initial capacity to avoid expensive resizing
            return CacheBuilderSpec.parse(cacheSpec.stream().collect(Collectors.joining(",")))
        }

        private fun getMaintenanceRunnable(
            cache: LoadingCache<ZoneKey?, Zone?>?,
            type: ZoneCacheType?,
            refreshInterval: Int
        ): Runnable? {
            return Runnable {
                ZoneManager.Companion.LOGGER.info(
                    "starting maintenance on " + type.toString() + " zone cache: " + Integer.toHexString(
                        cache.hashCode()
                    ) + ". Current size: " + cache.size()
                )
                cache.cleanUp()
                for (zoneKey in cache.asMap().keys) {
                    try {
                        if (ZoneManager.Companion.signatureManager.needsRefresh(type, zoneKey, refreshInterval)) {
                            cache.refresh(zoneKey)
                        }
                    } catch (ex: RuntimeException) {
                        ZoneManager.Companion.LOGGER.fatal(
                            "RuntimeException caught on " + zoneKey.javaClass.simpleName + " for " + zoneKey.getName(),
                            ex
                        )
                    }
                }
                ZoneManager.Companion.LOGGER.info(
                    "completed maintenance on " + type.toString() + " zone cache: " + Integer.toHexString(
                        cache.hashCode()
                    )
                )
            }
        }

        private fun initZoneDirectory() {
            synchronized(ZoneManager.Companion.LOGGER) {
                if (ZoneManager.Companion.zoneDirectory.exists()) {
                    for (entry in ZoneManager.Companion.zoneDirectory.list()) {
                        val zone: File = File(ZoneManager.Companion.zoneDirectory.getPath(), entry)
                        zone.delete()
                    }
                    val deleted: Boolean = ZoneManager.Companion.zoneDirectory.delete()
                    if (!deleted) {
                        ZoneManager.Companion.LOGGER.warn("Unable to delete " + ZoneManager.Companion.zoneDirectory)
                    }
                }
                ZoneManager.Companion.zoneDirectory.mkdir()
            }
        }

        @Throws(IOException::class)
        private fun writeZone(zone: Zone?) {
            synchronized(ZoneManager.Companion.LOGGER) {
                if (!ZoneManager.Companion.zoneDirectory.exists() && !ZoneManager.Companion.zoneDirectory.mkdirs()) {
                    ZoneManager.Companion.LOGGER.error(ZoneManager.Companion.zoneDirectory.getAbsolutePath() + " directory does not exist and cannot be created!")
                }
                val zoneFile: File = File(ZoneManager.Companion.getZoneDirectory(), zone.getOrigin().toString())
                val w = FileWriter(zoneFile)
                ZoneManager.Companion.LOGGER.info("writing: " + zoneFile.absolutePath)
                IOUtils.write(zone.toMasterFile(), w)
                w.flush()
                w.close()
            }
        }

        private fun createZoneCache(
            cacheType: ZoneCacheType?,
            spec: CacheBuilderSpec? = CacheBuilderSpec.parse("")
        ): LoadingCache<ZoneKey?, Zone?>? {
            val removalListener =
                RemovalListener<ZoneKey?, Zone?> { removal -> ZoneManager.Companion.LOGGER.debug(cacheType.toString() + " " + removal.key.javaClass.simpleName + " " + removal.key.getName() + " evicted from cache: " + removal.cause) }
            return CacheBuilder.from(spec).recordStats().removalListener(removalListener).build(
                object : CacheLoader<ZoneKey?, Zone?>() {
                    val writeZone = if (cacheType == ZoneCacheType.STATIC) true else false
                    @Throws(IOException::class, GeneralSecurityException::class)
                    override fun load(zoneKey: ZoneKey?): Zone? {
                        ZoneManager.Companion.LOGGER.debug("loading " + cacheType + " " + zoneKey.javaClass.simpleName + " " + zoneKey.getName())
                        return ZoneManager.Companion.loadZone(zoneKey, writeZone)
                    }

                    @Throws(IOException::class, GeneralSecurityException::class)
                    override fun reload(zoneKey: ZoneKey?, prevZone: Zone?): ListenableFuture<Zone?>? {
                        val zoneTask = ListenableFutureTask.create(
                            Callable<Zone?> { ZoneManager.Companion.loadZone(zoneKey, writeZone) })
                        ZoneManager.Companion.zoneExecutor.execute(zoneTask)
                        return zoneTask
                    }
                }
            )
        }

        @Throws(IOException::class, GeneralSecurityException::class)
        fun loadZone(zoneKey: ZoneKey?, writeZone: Boolean): Zone? {
            ZoneManager.Companion.LOGGER.debug("Attempting to load " + zoneKey.getName())
            val name = zoneKey.getName()
            var records = zoneKey.getRecords()
            zoneKey.updateTimestamp()
            if (zoneKey is SignedZoneKey) {
                records = ZoneManager.Companion.signatureManager.signZone(name, records, zoneKey as SignedZoneKey?)
            }
            val zone = Zone(name, records.toTypedArray())
            if (writeZone) {
                ZoneManager.Companion.writeZone(zone)
            }
            return zone
        }

        private fun getAllDeliveryServiceDomains(tr: TrafficRouter?): MutableMap<String?, DeliveryService?>? {
            val data = tr.getCacheRegister()
            val dsMap: MutableMap<String?, DeliveryService?> = HashMap()
            val tld: String =
                ZoneManager.Companion.getTopLevelDomain().toString(true) // Name.toString(true) - omit the trailing dot
            for (ds in data.deliveryServices.values) {
                var domain = ds.domain ?: continue
                if (domain.endsWith("+")) {
                    domain = domain.replace("\\+\\z".toRegex(), ".") + tld
                }
                if (domain.endsWith(tld)) {
                    dsMap[domain] = ds
                }
            }
            return dsMap
        }

        @Throws(IOException::class)
        private fun generateZones(
            tr: TrafficRouter?, zc: LoadingCache<ZoneKey?, Zone?>?, dzc: LoadingCache<ZoneKey?, Zone?>?,
            generationTasks: MutableList<Runnable?>?, primingTasks: BlockingQueue<Runnable?>?,
            newDomainsToZoneKeys: ConcurrentMap<String?, ZoneKey?>?
        ) {
            val dsMap: MutableMap<String?, DeliveryService?> = ZoneManager.Companion.getAllDeliveryServiceDomains(tr)
            val data = tr.getCacheRegister()
            val zoneMap: MutableMap<String?, MutableList<Record?>?> = HashMap()
            val superDomains: MutableMap<String?, MutableList<Record?>?> =
                ZoneManager.Companion.populateZoneMap(zoneMap, dsMap, data)
            val superRecords: MutableList<Record?> = ZoneManager.Companion.fillZones(
                zoneMap,
                dsMap,
                tr,
                zc,
                dzc,
                generationTasks,
                primingTasks,
                newDomainsToZoneKeys
            )
            val upstreamRecords: MutableList<Record?> = ZoneManager.Companion.fillZones(
                superDomains,
                dsMap,
                tr,
                superRecords,
                zc,
                dzc,
                generationTasks,
                primingTasks,
                newDomainsToZoneKeys
            )
            for (record in upstreamRecords) {
                if (record.getType() == Type.DS) {
                    ZoneManager.Companion.LOGGER.info("Publish this DS record in the parent zone: $record")
                }
            }
        }

        @Throws(IOException::class)
        private fun fillZones(
            zoneMap: MutableMap<String?, MutableList<Record?>?>?,
            dsMap: MutableMap<String?, DeliveryService?>?,
            tr: TrafficRouter?,
            zc: LoadingCache<ZoneKey?, Zone?>?,
            dzc: LoadingCache<ZoneKey?, Zone?>?,
            generationTasks: MutableList<Runnable?>?,
            primingTasks: BlockingQueue<Runnable?>?,
            newDomainsToZoneKeys: ConcurrentMap<String?, ZoneKey?>?
        ): MutableList<Record?>? {
            return ZoneManager.Companion.fillZones(
                zoneMap,
                dsMap,
                tr,
                null,
                zc,
                dzc,
                generationTasks,
                primingTasks,
                newDomainsToZoneKeys
            )
        }

        @Throws(IOException::class)
        private fun fillZones(
            zoneMap: MutableMap<String?, MutableList<Record?>?>?,
            dsMap: MutableMap<String?, DeliveryService?>?,
            tr: TrafficRouter?,
            superRecords: MutableList<Record?>?,
            zc: LoadingCache<ZoneKey?, Zone?>?,
            dzc: LoadingCache<ZoneKey?, Zone?>?,
            generationTasks: MutableList<Runnable?>?,
            primingTasks: BlockingQueue<Runnable?>?,
            newDomainsToZoneKeys: ConcurrentMap<String?, ZoneKey?>?
        ): MutableList<Record?>? {
            val hostname = InetAddress.getLocalHost().hostName.replace("\\..*".toRegex(), "")
            val records: MutableList<Record?> = ArrayList()
            for (domain in zoneMap.keys) {
                if (superRecords != null && !superRecords.isEmpty()) {
                    zoneMap.get(domain).addAll(superRecords)
                }
                records.addAll(
                    ZoneManager.Companion.createZone(
                        domain,
                        zoneMap,
                        dsMap,
                        tr,
                        zc,
                        dzc,
                        generationTasks,
                        primingTasks,
                        hostname,
                        newDomainsToZoneKeys
                    )
                )
            }
            return records
        }

        @Throws(IOException::class)
        private fun createZone(
            domain: String?,
            zoneMap: MutableMap<String?, MutableList<Record?>?>?,
            dsMap: MutableMap<String?, DeliveryService?>?,
            tr: TrafficRouter?,
            zc: LoadingCache<ZoneKey?, Zone?>?,
            dzc: LoadingCache<ZoneKey?, Zone?>?,
            generationTasks: MutableList<Runnable?>?,
            primingTasks: BlockingQueue<Runnable?>?,
            hostname: String?,
            newDomainsToZoneKeys: ConcurrentMap<String?, ZoneKey?>?
        ): MutableList<Record?>? {
            val ds = dsMap.get(domain)
            val data = tr.getCacheRegister()
            val trafficRouters = data.trafficRouters
            val config = data.config
            var ttl: JsonNode? = null
            var soa: JsonNode? = null
            if (ds != null) {
                ttl = ds.ttls
                soa = ds.soa
            } else {
                ttl = config["ttls"]
                soa = config["soa"]
            }
            val name: Name = ZoneManager.Companion.newName(domain)
            val list = zoneMap.get(domain)
            val admin: Name =
                ZoneManager.Companion.newName(ZoneUtils.getAdminString(soa, "admin", "traffic_ops", domain))
            list.add(
                SOARecord(
                    name,
                    DClass.IN,
                    ZoneUtils.getLong(ttl, "SOA", 86400),
                    ZoneManager.Companion.getGlueName(ds, trafficRouters[hostname], name, hostname),
                    admin,
                    ZoneUtils.getLong(soa, "serial", ZoneUtils.getSerial(data.stats)),
                    ZoneUtils.getLong(soa, "refresh", 28800),
                    ZoneUtils.getLong(soa, "retry", 7200),
                    ZoneUtils.getLong(soa, "expire", 604800),
                    ZoneUtils.getLong(soa, "minimum", 60)
                )
            )
            ZoneManager.Companion.addTrafficRouters(list, trafficRouters, name, ttl, domain, ds, tr)
            ZoneManager.Companion.addStaticDnsEntries(list, ds, domain)
            val records: MutableList<Record?> = ArrayList()
            val maxTTL = ZoneUtils.getMaximumTTL(list)
            try {
                records.addAll(ZoneManager.Companion.signatureManager.generateDSRecords(name, maxTTL))
                list.addAll(ZoneManager.Companion.signatureManager.generateDNSKEYRecords(name, maxTTL))
            } catch (ex: NoSuchAlgorithmException) {
                ZoneManager.Companion.LOGGER.fatal("Unable to create zone: " + ex.message, ex)
            }
            ZoneManager.Companion.primeZoneCache(
                domain,
                name,
                list,
                tr,
                zc,
                dzc,
                generationTasks,
                primingTasks,
                ds,
                newDomainsToZoneKeys
            )
            return records
        }

        private fun primeZoneCache(
            domain: String?,
            name: Name?,
            list: MutableList<Record?>?,
            tr: TrafficRouter?,
            zc: LoadingCache<ZoneKey?, Zone?>?,
            dzc: LoadingCache<ZoneKey?, Zone?>?,
            generationTasks: MutableList<Runnable?>?,
            primingTasks: BlockingQueue<Runnable?>?,
            ds: DeliveryService?,
            newDomainsToZoneKeys: ConcurrentMap<String?, ZoneKey?>?
        ) {
            generationTasks.add(Runnable {
                try {
                    val newZoneKey: ZoneKey = ZoneManager.Companion.signatureManager.generateZoneKey(name, list)
                    if (tr.isDnssecZoneDiffingEnabled() && ZoneManager.Companion.domainsToZoneKeys.containsKey(domain)) {
                        val oldZoneKey: ZoneKey = ZoneManager.Companion.domainsToZoneKeys.get(domain)
                        if (ZoneManager.Companion.zonesAreEqual(newZoneKey.records, oldZoneKey.records)) {
                            val oldZone: Zone = ZoneManager.Companion.zoneCache.getIfPresent(oldZoneKey)
                            if (oldZone != null) {
                                ZoneManager.Companion.LOGGER.info("found matching ZoneKey for $domain - copying from current Zone cache into new Zone cache - no re-signing necessary")
                                zc.put(oldZoneKey, oldZone)
                                newDomainsToZoneKeys[domain] = oldZoneKey
                                return@add
                            }
                            ZoneManager.Companion.LOGGER.warn("found matching ZoneKey for $domain but the Zone was not found in the Zone cache")
                        } else {
                            ZoneManager.Companion.LOGGER.info("new zone for $domain is not equal to the old zone - re-signing necessary")
                        }
                    }
                    val zone = zc.get(newZoneKey) // cause the zone to be loaded into the new cache
                    if (tr.isDnssecZoneDiffingEnabled()) {
                        newDomainsToZoneKeys[domain] = newZoneKey
                    }
                    val data = tr.getCacheRegister()
                    val config = data.config
                    val primeDynCache = JsonUtils.optBoolean(config, "dynamic.cache.primer.enabled", true)
                    if (!primeDynCache || ds == null || !ds.isDns && !tr.isEdgeHTTPRouting()) {
                        return@add
                    }
                    primingTasks.add(Runnable {
                        try {
                            // prime the dynamic zone cache
                            if (ds.isDns) {
                                ZoneManager.Companion.primeDNSDeliveryServices(domain, name, tr, dzc, zone, ds, data)
                            } else if (!ds.isDns && tr.isEdgeHTTPRouting()) {
                                ZoneManager.Companion.primeHTTPDeliveryServices(domain, tr, dzc, zone, ds, data)
                            }
                        } catch (ex: TextParseException) {
                            ZoneManager.Companion.LOGGER.fatal("Unable to prime dynamic zone $domain", ex)
                        }
                    })
                } catch (ex: ExecutionException) {
                    ZoneManager.Companion.LOGGER.fatal("Unable to load zone into cache: " + ex.message, ex)
                }
            })
        }

        @Throws(TextParseException::class)
        private fun primeHTTPDeliveryServices(
            domain: String?, tr: TrafficRouter?, dzc: LoadingCache<ZoneKey?, Zone?>?,
            zone: Zone?, ds: DeliveryService?, data: CacheRegister?
        ) {
            val edgeName: Name = ZoneManager.Companion.newName(ds.getRoutingName(), domain)
            ZoneManager.Companion.LOGGER.info("Priming $edgeName")
            val request = DNSRequest(zone, edgeName, Type.A)
            request.isDnssec = ZoneManager.Companion.signatureManager.isDnssecEnabled()
            request.hostname = edgeName.toString(true) // Name.toString(true) - omit the trailing dot

            // prime the miss case first
            try {
                val result = DNSRouteResult()
                result.addresses = tr.selectTrafficRoutersMiss(request.zoneName, ds)
                ZoneManager.Companion.fillDynamicZone(dzc, zone, request, result)
            } catch (ex: GeolocationException) {
                ZoneManager.Companion.LOGGER.warn(ex, ex)
            }

            // prime answers for each of our edge locations
            for (trLocation in data.getEdgeTrafficRouterLocations()) {
                try {
                    val result = DNSRouteResult()
                    result.addresses = tr.selectTrafficRoutersLocalized(trLocation.geolocation, request.zoneName, ds)
                    ZoneManager.Companion.fillDynamicZone(dzc, zone, request, result)
                } catch (ex: GeolocationException) {
                    ZoneManager.Companion.LOGGER.warn(ex, ex)
                }
            }
        }

        @Throws(TextParseException::class)
        private fun primeDNSDeliveryServices(
            domain: String?, name: Name?, tr: TrafficRouter?, dzc: LoadingCache<ZoneKey?, Zone?>?,
            zone: Zone?, ds: DeliveryService?, data: CacheRegister?
        ) {
            val edgeName: Name = ZoneManager.Companion.newName(ds.getRoutingName(), domain)
            val config = data.getConfig()
            val primerLimit =
                JsonUtils.optInt(config, "dynamic.cache.primer.limit", ZoneManager.Companion.DEFAULT_PRIMER_LIMIT)
            ZoneManager.Companion.LOGGER.info("Priming $edgeName")
            val request = DNSRequest(zone, name, Type.A)
            request.isDnssec = ZoneManager.Companion.signatureManager.isDnssecEnabled()
            request.hostname = edgeName.toString(true) // Name.toString(true) - omit the trailing dot
            for (cacheLocation in data.getCacheLocations()) {
                val caches = tr.selectCachesByCZ(ds, cacheLocation, IPVersions.ANY) ?: continue

                // calculate number of permutations if maxDnsIpsForLocation > 0 and we're not using consistent DNS routing
                var p = 1
                if (ds.isDns() && ds.getMaxDnsIps() > 0 && !tr.isConsistentDNSRouting() && caches.size > ds.getMaxDnsIps()) {
                    for (c in caches.size downTo caches.size - ds.getMaxDnsIps() + 1) {
                        p *= c
                    }
                }
                val pset: MutableSet<MutableList<InetRecord?>?> = HashSet()
                for (i in 0 until primerLimit) {
                    val records = tr.inetRecordsFromCaches(ds, caches, request)
                    val result = DNSRouteResult()
                    result.addresses = records
                    if (!pset.contains(records)) {
                        if (!tr.isEdgeDNSRouting()) {
                            ZoneManager.Companion.fillDynamicZone(dzc, zone, request, result)
                        } else {
                            try {
                                val hitResult = DNSRouteResult()
                                val hitRecords =
                                    tr.selectTrafficRoutersLocalized(cacheLocation.geolocation, request.zoneName, ds)
                                hitRecords.addAll(records)
                                hitResult.addresses = hitRecords
                                ZoneManager.Companion.fillDynamicZone(dzc, zone, request, hitResult)
                            } catch (ex: GeolocationException) {
                                ZoneManager.Companion.LOGGER.warn(ex, ex)
                            }
                        }
                        pset.add(records)
                    }
                    ZoneManager.Companion.LOGGER.debug("Primed " + ds.getId() + " @ " + cacheLocation.id + "; permutation " + pset.size + "/" + p)
                    if (pset.size == p) {
                        break
                    }
                }
            }
        }

        // Check if the zones are equal except for the SOA record serial number, NSEC, or RRSIG records
        fun zonesAreEqual(newRecords: MutableList<Record?>?, oldRecords: MutableList<Record?>?): Boolean {
            val oldRecordsCopy = oldRecords.stream()
                .filter { r: Record? -> r !is NSECRecord && r !is RRSIGRecord }
                .collect(Collectors.toList())
            val newRecordsCopy = newRecords.stream()
                .filter { r: Record? -> r !is NSECRecord && r !is RRSIGRecord }
                .collect(Collectors.toList())
            if (oldRecordsCopy.size != newRecordsCopy.size) {
                return false
            }
            Collections.sort(oldRecordsCopy)
            Collections.sort(newRecordsCopy)
            for (i in newRecordsCopy.indices) {
                val newRec = newRecordsCopy[i]
                val oldRec = oldRecordsCopy[i]
                if (newRec is SOARecord && oldRec is SOARecord) {
                    val newSOA = newRec as SOARecord?
                    val oldSOA = oldRec as SOARecord?
                    // cmpSOA is a copy of newSOA except with the serial of oldSOA
                    val cmpSOA = SOARecord(
                        newSOA.getName(), newSOA.getDClass(), newSOA.getTTL(),
                        newSOA.getHost(), newSOA.getAdmin(), oldSOA.getSerial(), newSOA.getRefresh(),
                        newSOA.getRetry(), newSOA.getExpire(), newSOA.getMinimum()
                    )
                    if (oldSOA == cmpSOA && oldSOA.ttl == cmpSOA.ttl) {
                        continue
                    }
                    return false
                }
                if (newRec == oldRec && newRec.getTTL() == oldRec.getTTL()) {
                    continue
                }
                return false
            }
            return true
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        private fun addStaticDnsEntries(list: MutableList<Record?>?, ds: DeliveryService?, domain: String?) {
            if (ds != null && ds.staticDnsEntries != null) {
                val entryList = ds.staticDnsEntries
                for (staticEntry in entryList) {
                    try {
                        val type = JsonUtils.getString(staticEntry, "type").toUpperCase()
                        val jsName = JsonUtils.getString(staticEntry, "name")
                        val value = JsonUtils.getString(staticEntry, "value")
                        val name: Name = ZoneManager.Companion.newName(jsName, domain)
                        var ttl: Long = optInt(staticEntry, "ttl").toLong()
                        if (ttl == 0L) {
                            ttl = ZoneUtils.getLong(ds.ttls, type, 60)
                        }
                        when (type) {
                            "A" -> list.add(ARecord(name, DClass.IN, ttl, InetAddress.getByName(value)))
                            "AAAA" -> list.add(AAAARecord(name, DClass.IN, ttl, InetAddress.getByName(value)))
                            "CNAME" -> list.add(CNAMERecord(name, DClass.IN, ttl, Name(value)))
                            "TXT" -> list.add(TXTRecord(name, DClass.IN, ttl, String(value)))
                        }
                    } catch (ex: JsonUtilsException) {
                        ZoneManager.Companion.LOGGER.error(ex)
                    }
                }
            }
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        private fun addTrafficRouters(
            list: MutableList<Record?>?, trafficRouters: JsonNode?, name: Name?,
            ttl: JsonNode?, domain: String?, ds: DeliveryService?, tr: TrafficRouter?
        ) {
            val ip6RoutingEnabled = if (ds == null || ds != null && ds.isIp6RoutingEnabled) true else false
            val keyIter = trafficRouters.fieldNames()
            while (keyIter.hasNext()) {
                val key = keyIter.next()
                val trJo = trafficRouters.get(key)
                if (!trJo.has("status") || "OFFLINE" == trJo["status"].asText() || "ADMIN_DOWN" == trJo["status"].asText()) {
                    continue
                }
                val trName: Name = ZoneManager.Companion.newName(key, domain)

                // NSRecords will be replaced later if tr.isEdgeDNSRouting() is true; we need these to allow stub zones to be signed, etc
                list.add(
                    NSRecord(
                        name,
                        DClass.IN,
                        ZoneUtils.getLong(ttl, "NS", 60),
                        ZoneManager.Companion.getGlueName(ds, trJo, name, key)
                    )
                )
                list.add(
                    ARecord(
                        trName,
                        DClass.IN, ZoneUtils.getLong(ttl, "A", 60),
                        InetAddress.getByName(optString(trJo, ZoneManager.Companion.IP))
                    )
                )
                var ip6 = trJo["ip6"].asText()
                if (ip6 != null && !ip6.isEmpty() && ip6RoutingEnabled) {
                    ip6 = ip6.replace("/.*".toRegex(), "")
                    list.add(
                        AAAARecord(
                            trName,
                            DClass.IN,
                            ZoneUtils.getLong(ttl, ZoneManager.Companion.AAAA, 60),
                            Inet6Address.getByName(ip6)
                        )
                    )
                }

                // only add static routing name entries for HTTP DSs if necessary
                if (ds != null && !ds.isDns && !tr.isEdgeHTTPRouting()) {
                    ZoneManager.Companion.addHttpRoutingRecords(
                        list,
                        ds.routingName,
                        domain,
                        trJo,
                        ttl,
                        ip6RoutingEnabled
                    )
                }
            }
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        private fun addHttpRoutingRecords(
            list: MutableList<Record?>?,
            routingName: String?,
            domain: String?,
            trJo: JsonNode?,
            ttl: JsonNode?,
            addTrafficRoutersAAAA: Boolean
        ) {
            val trName: Name = ZoneManager.Companion.newName(routingName, domain)
            list.add(
                ARecord(
                    trName,
                    DClass.IN,
                    ZoneUtils.getLong(ttl, "A", 60),
                    InetAddress.getByName(optString(trJo, ZoneManager.Companion.IP))
                )
            )
            var ip6: String = optString(trJo, ZoneManager.Companion.IP6)
            if (addTrafficRoutersAAAA && ip6 != null && !ip6.isEmpty()) {
                ip6 = ip6.replace("/.*".toRegex(), "")
                list.add(
                    AAAARecord(
                        trName,
                        DClass.IN,
                        ZoneUtils.getLong(ttl, ZoneManager.Companion.AAAA, 60),
                        Inet6Address.getByName(ip6)
                    )
                )
            }
        }

        @Throws(TextParseException::class)
        private fun newName(hostname: String?, domain: String?): Name? {
            return ZoneManager.Companion.newName("$hostname.$domain")
        }

        @Throws(TextParseException::class)
        private fun newName(fqdn: String?): Name? {
            return if (fqdn.endsWith(".")) {
                Name(fqdn)
            } else {
                Name("$fqdn.")
            }
        }

        @Throws(TextParseException::class)
        private fun getGlueName(ds: DeliveryService?, trJo: JsonNode?, name: Name?, trName: String?): Name? {
            return if (ds == null && trJo != null && trJo.has("fqdn") && trJo["fqdn"].textValue() != null) {
                ZoneManager.Companion.newName(trJo["fqdn"].textValue())
            } else {
                val superDomain = Name(Name(name.toString(true)), 1)
                ZoneManager.Companion.newName(trName, superDomain.toString())
            }
        }

        @Throws(IOException::class)
        private fun populateZoneMap(
            zoneMap: MutableMap<String?, MutableList<Record?>?>?,
            dsMap: MutableMap<String?, DeliveryService?>?, data: CacheRegister?
        ): MutableMap<String?, MutableList<Record?>?>? {
            val superDomains: MutableMap<String?, MutableList<Record?>?> = HashMap()
            for (domain in dsMap.keys) {
                zoneMap[domain] = ArrayList()
            }
            for (c in data.getCacheMap().values) {
                for (dsr in c.deliveryServices) {
                    val ds = data.getDeliveryService(dsr.deliveryServiceId)
                    if (ds == null) {
                        ZoneManager.Companion.LOGGER.warn("Content server " + c.fqdn + " has delivery service " + dsr.deliveryServiceId + " assigned, but the delivery service was not found. Skipping.")
                        continue
                    }
                    val fqdn = dsr.fqdn
                    val parts: Array<String?> = fqdn.split("\\.".toRegex(), 2).toTypedArray()
                    val host = parts[0]
                    val domain = parts[1]
                    dsMap[domain] = ds
                    val zholder = zoneMap.computeIfAbsent(
                        domain,
                        Function<String?, MutableList<Record?>?> { k: String? -> ArrayList() })
                    val superdomain = domain.split("\\.".toRegex(), 2).toTypedArray()[1]
                    if (!superDomains.containsKey(superdomain)) {
                        superDomains[superdomain] = ArrayList()
                    }
                    if (ds.isDns && host.equals(ds.routingName, ignoreCase = true)) {
                        continue
                    }
                    try {
                        val name: Name = ZoneManager.Companion.newName(fqdn)
                        val ttl = ds.ttls
                        val ip4 = c.ip4
                        if (ip4 != null) {
                            try {
                                zholder.add(ARecord(name, DClass.IN, ZoneUtils.getLong(ttl, "A", 60), ip4))
                            } catch (e: IllegalArgumentException) {
                                ZoneManager.Companion.LOGGER.warn("$e : $ip4", e)
                            }
                        }
                        val ip6 = c.ip6
                        if (ip6 != null && ds.isIp6RoutingEnabled) {
                            try {
                                zholder.add(
                                    AAAARecord(
                                        name,
                                        DClass.IN,
                                        ZoneUtils.getLong(ttl, ZoneManager.Companion.AAAA, 60),
                                        ip6
                                    )
                                )
                            } catch (e: IllegalArgumentException) {
                                ZoneManager.Companion.LOGGER.warn("$e : $ip6", e)
                            }
                        }
                    } catch (e: TextParseException) {
                        ZoneManager.Companion.LOGGER.error(
                            "Caught fatal exception while generating zone data for $fqdn!",
                            e
                        )
                    }
                }
            }
            return superDomains
        }

        private fun fillDynamicZone(
            dzc: LoadingCache<ZoneKey?, Zone?>?,
            staticZone: Zone?,
            request: DNSRequest?,
            result: DNSRouteResult?
        ): Zone? {
            if (result == null || result.addresses == null) {
                return null
            }
            try {
                var nsSeen = false
                val records: MutableList<Record?> = ArrayList()
                for (address in result.addresses) {
                    val ds = result.deliveryService
                    var name = request.getName()
                    if (address.type == Type.NS) {
                        name = staticZone.getOrigin()
                    } else if (ds != null && (address.type == Type.A || address.type == Type.AAAA)) {
                        val routingName = ds.routingName
                        name = Name(routingName, staticZone.getOrigin()) // routingname.ds.cdn.tld
                    }
                    val record: Record = ZoneManager.Companion.createRecord(name, address)
                    if (record != null) {
                        records.add(record)
                    }
                    if (record is NSRecord) {
                        nsSeen = true
                    }
                }

                // populate the dynamic zone with any static entries that aren't NS records or routing names
                val it: MutableIterator<RRset?>? = staticZone.iterator()
                while (it.hasNext()) {
                    val rrset = it.next()
                    val rit: MutableIterator<Record?>? = rrset.rrs()
                    while (rit.hasNext()) {
                        val r = rit.next()
                        if (r is NSRecord) { // NSRecords are handled below
                            continue
                        }
                        records.add(r)
                    }
                }
                if (!records.isEmpty()) {
                    if (!nsSeen) {
                        records.addAll(ZoneManager.Companion.createZoneNSRecords(staticZone))
                    }
                    try {
                        val zoneKey: ZoneKey = ZoneManager.Companion.signatureManager.generateDynamicZoneKey(
                            staticZone.getOrigin(),
                            records,
                            request.isDnssec()
                        )
                        return dzc.get(zoneKey)
                    } catch (e: ExecutionException) {
                        ZoneManager.Companion.LOGGER.error(e, e)
                    }
                    return Zone(staticZone.getOrigin(), records.toTypedArray())
                }
            } catch (e: IOException) {
                ZoneManager.Companion.LOGGER.error(e.message, e)
            }
            return null
        }

        @Throws(TextParseException::class)
        private fun createRecord(name: Name?, address: InetRecord?): Record? {
            var record: Record? = null
            if (address.isAlias()) {
                record =
                    CNAMERecord(name, DClass.IN, address.getTTL(), ZoneManager.Companion.newName(address.getAlias()))
            } else if (address.getType() == Type.NS) {
                val tld: Name = ZoneManager.Companion.getTopLevelDomain()
                var target = address.getTarget()

                // fix up target to be TR host name plus top level domain
                if (name.subdomain(tld) && name != tld) {
                    target = String.format("%s.%s", target.split("\\.".toRegex(), 2).toTypedArray()[0], tld.toString())
                }
                record = NSRecord(name, DClass.IN, address.getTTL(), ZoneManager.Companion.newName(target))
            } else if (address.isInet4()) { // address instanceof Inet4Address
                record = ARecord(name, DClass.IN, address.getTTL(), address.getAddress())
            } else if (address.isInet6()) {
                record = AAAARecord(name, DClass.IN, address.getTTL(), address.getAddress())
            }
            return record
        }

        @Throws(IOException::class)
        private fun createZoneNSRecords(staticZone: Zone?): MutableList<Record?>? {
            val records: MutableList<Record?> = ArrayList()
            val ns: MutableIterator<Record?>? = staticZone.getNS().rrs()
            while (ns.hasNext()) {
                records.add(ns.next())
            }
            return records
        }

        fun getZoneDirectory(): File? {
            return ZoneManager.Companion.zoneDirectory
        }

        fun setZoneDirectory(zoneDirectory: File?) {
            ZoneManager.Companion.zoneDirectory = zoneDirectory
        }

        fun getTopLevelDomain(): Name? {
            return ZoneManager.Companion.topLevelDomain
        }

        private fun setTopLevelDomain(topLevelDomain: Name?) {
            ZoneManager.Companion.topLevelDomain = topLevelDomain
        }
    }

    init {
        ZoneManager.Companion.initTopLevelDomain(tr.getCacheRegister())
        initSignatureManager(tr.getCacheRegister(), trafficOpsUtils, trafficRouterManager)
        ZoneManager.Companion.initZoneCache(tr)
        trafficRouter = tr
        this.statTracker = statTracker
    }
}