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
package org.apache.traffic_control.traffic_router.core.dnsimport

import org.apache.logging.log4j.LogManagerimport

org.apache.traffic_control.traffic_router.core.dns.DNSAccessRecordimport org.apache.traffic_control.traffic_router.core.dns.NameServerimport org.apache.traffic_control.traffic_router.core.dns.ZoneManagerimport org.apache.traffic_control.traffic_router.core.ds.DeliveryServiceimport org.apache.traffic_control.traffic_router.core.router.TrafficRouterManagerimport org.xbill.DNS.*import java.net.InetAddressimport

java.util.* org.springframework.web.bind.annotation .RequestMapping
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
import org.apache.traffic_control.traffic_router.core.edge.CacheLocation
import org.apache.traffic_control.traffic_router.core.edge.Node.IPVersions
import org.apache.traffic_control.traffic_router.api.controllers.ConsistentHashController
import org.apache.traffic_control.traffic_router.core.ds.DeliveryService
import java.net.URLDecoder
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
import java.net.MalformedURLException
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import org.apache.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import java.lang.StringBuilder
import org.apache.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import org.apache.traffic_control.traffic_router.core.request.DNSRequest
import org.apache.traffic_control.traffic_router.core.edge.InetRecord
import java.net.InetAddress
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
import java.net.ServerSocket
import org.apache.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import org.apache.traffic_control.traffic_router.core.dns.protocol.TCP
import java.io.DataInputStream
import java.net.DatagramSocket
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
import org.apache.traffic_control.traffic_router.core.edge.CacheRegister
import org.apache.traffic_control.traffic_router.core.dns.SignatureManager
import org.apache.traffic_control.traffic_router.core.router.DNSRouteResult
import java.net.Inet6Address
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
import java.net.Inet4Address
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
import java.net.URISyntaxException
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
import org.junit.Before
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
import org.junit.BeforeClass
import org.apache.traffic_control.traffic_router.core.TestBase
import org.junit.AfterClass
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
import java.net.SocketTimeoutException
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
import org.junit.FixMethodOrder
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
import java.net.InetSocketAddress
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

class NameServer {
    private var ecsEnable = false
    private var ecsEnabledDses: MutableSet<DeliveryService?>? = HashSet()

    /**
     *
     */
    private var trafficRouterManager: TrafficRouterManager? = null

    /**
     * Queries the zones based on the request and returns the appropriate response.
     *
     * @param request
     * the query message
     * @param clientAddress
     * the IP address of the client
     * @return a response message
     */
    fun query(request: Message?, clientAddress: InetAddress?, builder: DNSAccessRecord.Builder?): Message? {
        val response = Message()
        try {
            NameServer.Companion.addQuestion(request, response)
            addAnswers(request, response, clientAddress, builder)
        } catch (e: RuntimeException) {
            NameServer.Companion.LOGGER.error(e.message, e)
            response.header.rcode = Rcode.SERVFAIL
        }
        return response
    }

    private fun addAnswers(request: Message?, response: Message?, clientAddress: InetAddress?, builder: DNSAccessRecord.Builder?) {
        val question = request.getQuestion()
        if (question != null) {
            val qclass = question.dClass
            val qname = question.name
            val qopt = request.getOPT()
            var list: MutableList<EDNSOption?>? = Collections.EMPTY_LIST
            var dnssecRequest = false
            var qtype = question.type
            var flags = 0
            if (qopt != null && qopt.version > NameServer.Companion.MAX_SUPPORTED_EDNS_VERS) {
                response.getHeader().rcode = Rcode.NOTIMP
                val opt = OPTRecord(0, Rcode.BADVERS, NameServer.Companion.MAX_SUPPORTED_EDNS_VERS)
                response.addRecord(opt, Section.ADDITIONAL)
                return
            }
            if (qclass != DClass.IN && qclass != DClass.ANY) {
                response.getHeader().rcode = Rcode.REFUSED
                return
            }
            if (qopt != null && qopt.flags and ExtendedFlags.DO != 0) {
                flags = NameServer.Companion.FLAG_DNSSECOK
                dnssecRequest = true
            }
            if (qtype == Type.SIG || qtype == Type.RRSIG) {
                qtype = Type.ANY
                flags = flags or NameServer.Companion.FLAG_SIGONLY
            }
            // Get list of options matching client subnet option code (8)
            if (qopt != null) {
                list = qopt.getOptions(EDNSOption.Code.CLIENT_SUBNET)
            }
            var ipaddr: InetAddress? = null
            var nmask = 0
            if (isEcsEnable(qname)) {
                for (option in list) {
                    assert(option is ClientSubnetOption)
                    // If there are multiple ClientSubnetOptions in the Option RR, then
                    // choose the one with longest source prefix. RFC 7871
                    if ((option as ClientSubnetOption).sourceNetmask > nmask) {
                        nmask = (option as ClientSubnetOption).sourceNetmask
                        ipaddr = (option as ClientSubnetOption).address
                    }
                }
            }
            if (ipaddr != null && isEcsEnable(qname)) {
                builder.client(ipaddr)
                NameServer.Companion.LOGGER.debug("DNS: Using Client IP Address from ECS Option" + ipaddr.hostAddress + "/"
                        + nmask)
                lookup(qname, qtype, ipaddr, response, flags, dnssecRequest, builder)
            } else {
                lookup(qname, qtype, clientAddress, response, flags, dnssecRequest, builder)
            }
            if (response.getHeader().rcode == Rcode.REFUSED) {
                return
            }

            // Check if we had incoming ClientSubnetOption in Option RR, then we need
            // to return with the response, setting the scope subnet as well
            if (nmask != 0 && isEcsEnable(qname)) {
                val cso = ClientSubnetOption(nmask, nmask, ipaddr)
                val csoList: MutableList<ClientSubnetOption?> = ArrayList(1)
                csoList.add(cso)
                // OptRecord Arguments: payloadSize = 1280, xrcode = 0, version=0, flags=0, option List
                val opt = OPTRecord(1280, 0, 0, 0, csoList)
                response.addRecord(opt, Section.ADDITIONAL)
            }
            if (qopt != null && flags == NameServer.Companion.FLAG_DNSSECOK) {
                val optflags = ExtendedFlags.DO
                val opt = OPTRecord(1280, 0.toByte().toInt(), 0.toByte().toInt(), optflags)
                response.addRecord(opt, Section.ADDITIONAL)
            }
        }
    }

    private fun isDeliveryServiceEcsEnabled(name: Name?): Boolean {
        var isEnabled = false
        for (ds in ecsEnabledDses) {
            var domain: String = ds.getDomain() ?: continue
            if (domain.endsWith("+")) {
                domain = domain.replace("\\+\\z".toRegex(), ".") + ZoneManager.Companion.getTopLevelDomain()
            }
            if (name.relativize(Name.root).toString().contains(domain)) {
                isEnabled = true
                break
            }
        }
        return isEnabled
    }

    private fun lookup(qname: Name?, qtype: Int, clientAddress: InetAddress?, response: Message?, flags: Int, dnssecRequest: Boolean, builder: DNSAccessRecord.Builder?) {
        lookup(qname, qtype, clientAddress, null, response, 0, flags, dnssecRequest, builder)
    }

    private fun lookup(qname: Name?, qtype: Int, clientAddress: InetAddress?, incomingZone: Zone?, response: Message?, iteration: Int, flags: Int, dnssecRequest: Boolean, builder: DNSAccessRecord.Builder?) {
        if (iteration > NameServer.Companion.MAX_ITERATIONS) {
            return
        }
        var zone = incomingZone

        // this allows us to locate zones for which we are authoritative
        if (zone == null || !qname.subdomain(zone.origin)) {
            zone = trafficRouterManager.getTrafficRouter().getZone(qname, qtype, clientAddress, dnssecRequest, builder)
        }

        // null means we did not find a zone for which we are authoritative
        if (zone == null) {
            if (iteration == 0) {
                // refuse the query if we're not authoritative and we're not recursing
                response.getHeader().rcode = Rcode.REFUSED
            }
            return
        }
        val sr = zone.findRecords(qname, qtype)
        if (sr.isSuccessful) {
            for (answer in sr.answers()) {
                NameServer.Companion.addRRset(qname, response, answer, Section.ANSWER, flags)
            }
            NameServer.Companion.addAuthority(zone, response, flags)
        } else if (sr.isCNAME) {
            /*
			 * This is an ugly hack to work around the answers() method not working for CNAMEs.
			 * A CNAME results in isSuccessful() being false, and answers() requires isSuccessful()
			 * to be true. Because of this, we can either use reflection (slow) or use the getNS() method, which
			 * returns the RRset stored internally in "data" and is not actually specific to NS records.
			 * Our CNAME and RRSIGs are in this RRset, so use getNS() despite its name.
			 * Refer to the dnsjava SetResponse code for more information.
			 */
            val rrset = sr.ns
            NameServer.Companion.addRRset(qname, response, rrset, Section.ANSWER, flags)

            /*
			 * Allow recursive lookups for CNAME targets; the logic above allows us to
			 * ensure that we only recurse for domains for which we are authoritative.
			 */lookup(sr.cname.target, qtype, clientAddress, zone, response, iteration + 1, flags, dnssecRequest, builder)
        } else if (sr.isNXDOMAIN) {
            response.getHeader().rcode = Rcode.NXDOMAIN
            response.getHeader().setFlag(Flags.AA.toInt())
            NameServer.Companion.addDenialOfExistence(qname, zone, response, flags)
            NameServer.Companion.addSOA(zone, response, Section.AUTHORITY, flags)
        } else if (sr.isNXRRSET) {
            /*
			 * Per RFC 2308 NODATA is inferred by having no records;
			 * NXRRSET is discussed in RFC 2136, but that RFC is for Dynamic DNS updates.
			 * We'll ignore the NXRRSET from the API, and allow the client resolver to
			 * deal with NODATA per RFC 2308:
			 *   "NODATA" - a pseudo RCODE which indicates that the name is valid, for
			 *   the given class, but are no records of the given type.
			 *   A NODATA response has to be inferred from the answer.
			 */

            // The requirements for this are described in RFC 7129
            if (flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) != 0) {
                val ndsr = zone.findRecords(qname, Type.NSEC)
                if (ndsr.isSuccessful) {
                    for (answer in ndsr.answers()) {
                        NameServer.Companion.addRRset(qname, response, answer, Section.AUTHORITY, flags)
                    }
                }
            }
            NameServer.Companion.addSOA(zone, response, Section.AUTHORITY, flags)
            response.getHeader().setFlag(Flags.AA.toInt())
        }
    }

    fun getTrafficRouterManager(): TrafficRouterManager? {
        return trafficRouterManager
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun destroy() {
        /*
		 * Yes, this is odd. We need to call destroy on ZoneManager, but it's static, so
		 * we don't have a Spring bean ref; we do for NameServer, so this method is called.
		 * Given that we know we're shutting down and NameServer relies on ZoneManager,
		 * we'll call destroy while we can without hacking Spring too hard.
		 */
        ZoneManager.Companion.destroy()
    }

    fun isEcsEnable(qname: Name?): Boolean {
        return ecsEnable || isDeliveryServiceEcsEnabled(qname)
    }

    fun setEcsEnable(ecsEnable: Boolean) {
        this.ecsEnable = ecsEnable
    }

    fun getEcsEnabledDses(): MutableSet<DeliveryService?>? {
        return ecsEnabledDses
    }

    fun setEcsEnabledDses(ecsEnabledDses: MutableSet<DeliveryService?>?) {
        this.ecsEnabledDses = ecsEnabledDses
    }

    companion object {
        private const val MAX_SUPPORTED_EDNS_VERS = 0
        private const val MAX_ITERATIONS = 6
        private const val NUM_SECTIONS = 4
        private const val FLAG_DNSSECOK = 1
        private const val FLAG_SIGONLY = 2
        private val LOGGER = LogManager.getLogger(NameServer::class.java)
        private fun addAuthority(zone: Zone?, response: Message?, flags: Int) {
            val authority = zone.getNS()
            NameServer.Companion.addRRset(authority.name, response, authority, Section.AUTHORITY, flags)
            response.getHeader().setFlag(Flags.AA.toInt())
        }

        private fun addSOA(zone: Zone?, response: Message?, section: Int, flags: Int) {
            // we locate the SOA this way so that we can ensure we get the RRSIGs rather than just the one SOA Record
            val fsoa = zone.findRecords(zone.getOrigin(), Type.SOA)
            if (!fsoa.isSuccessful) {
                return
            }
            for (answer in fsoa.answers()) {
                NameServer.Companion.addRRset(zone.getOrigin(), response, NameServer.Companion.setNegativeTTL(answer, flags), section, flags)
            }
        }

        private fun addDenialOfExistence(qname: Name?, zone: Zone?, response: Message?, flags: Int) {
            // The requirements for this are described in RFC 7129
            if (flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) == 0) {
                return
            }
            var nsecSpan: RRset? = null
            var candidate: Name? = null
            val zi: MutableIterator<RRset?>? = zone.iterator()
            while (zi.hasNext()) {
                val rrset = zi.next()
                if (rrset.getType() != Type.NSEC) {
                    continue
                }
                val it: MutableIterator<Record?>? = rrset.rrs()
                while (it.hasNext()) {
                    val r = it.next()
                    val name = r.getName()
                    if (name.compareTo(qname) < 0 || candidate != null && name.compareTo(candidate) < 0) {
                        candidate = name
                        nsecSpan = rrset
                    } else if (name.compareTo(qname) > 0 && candidate != null) {
                        break
                    }
                }
            }
            if (candidate != null && nsecSpan != null) {
                NameServer.Companion.addRRset(candidate, response, nsecSpan, Section.AUTHORITY, flags)
            }
            val nxsr = zone.findRecords(zone.getOrigin(), Type.NSEC)
            if (nxsr.isSuccessful) {
                for (answer in nxsr.answers()) {
                    NameServer.Companion.addRRset(qname, response, answer, Section.AUTHORITY, flags)
                }
            }
        }

        private fun addQuestion(request: Message?, response: Message?) {
            response.getHeader().id = request.getHeader().id
            response.getHeader().setFlag(Flags.QR.toInt())
            if (request.getHeader().getFlag(Flags.RD.toInt())) {
                response.getHeader().setFlag(Flags.RD.toInt())
            }
            response.addRecord(request.getQuestion(), Section.QUESTION)
        }

        private fun addRRset(name: Name?, response: Message?, rrset: RRset?, section: Int, flags: Int) {
            for (s in 1 until NameServer.Companion.NUM_SECTIONS) {
                if (response.findRRset(name, rrset.getType(), s)) {
                    return
                }
            }
            val recordList: MutableList<Record?> = ArrayList()
            if (flags and NameServer.Companion.FLAG_SIGONLY == 0) {
                val it: MutableIterator<Record?>? = rrset.rrs()
                while (it.hasNext()) {
                    var r = it.next()
                    if (r.getName().isWild && !name.isWild()) {
                        r = r.withName(name)
                    }
                    recordList.add(r)
                }
            }

            // We prefer to shuffle the list over "cycling" as we could with rrset.rrs(true) above.
            Collections.shuffle(recordList)
            for (r in recordList) {
                response.addRecord(r, section)
            }
            if (flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) != 0) {
                val it: MutableIterator<Record?>? = rrset.sigs()
                while (it.hasNext()) {
                    var r = it.next()
                    if (r.getName().isWild && !name.isWild()) {
                        r = r.withName(name)
                    }
                    response.addRecord(r, section)
                }
            }
        }

        private fun setNegativeTTL(original: RRset?, flags: Int): RRset? {
            /*
		 * If DNSSEC is enabled/requested, use the SOA and sigs, otherwise
		 * lower the TTL on the SOA record to the minimum/ncache TTL,
		 * using whichever is lower. Behavior is defined in RFC 2308.
		 * In practice we see Vantio using the minimum from the SOA, while BIND
		 * uses the lowest TTL in the RRset in the authority section. When DNSSEC
		 * is enabled, the TTL for the RRsigs is derived from the minimum of the
		 * SOA via the jdnssec library, hence only modifying the TTL of the SOA
		 * itself in the non-DNSSEC use case below. We would invalidate the existing
		 * RRsigs if we modified the TTL of a signed RRset.
		 */

            // signed RRset and DNSSEC requested; return unmodified
            if (original.sigs().hasNext() && flags and (NameServer.Companion.FLAG_SIGONLY or NameServer.Companion.FLAG_DNSSECOK) != 0) {
                return original
            }
            val rrset = RRset()
            val it: MutableIterator<Record?>? = original.rrs()
            while (it.hasNext()) {
                var record = it.next()
                if (record is SOARecord) {
                    val soa = record as SOARecord?

                    // the value of the minimum field is less than the actual TTL; adjust
                    if (soa.getMinimum() != 0L || soa.getTTL() > soa.getMinimum()) {
                        record = SOARecord(soa.getName(), DClass.IN, soa.getMinimum(), soa.getHost(), soa.getAdmin(),
                                soa.getSerial(), soa.getRefresh(), soa.getRetry(), soa.getExpire(),
                                soa.getMinimum())
                    } // else use the unmodified record
                }
                rrset.addRR(record)
            }
            return rrset
        }
    }
}