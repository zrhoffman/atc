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
package org.apache.traffic_control.traffic_router.core.edgeimportimport

com.fasterxml.jackson.databind.JsonNodeimport org.apache.commons.lang3.builder.HashCodeBuilderimport org.apache.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReferenceimport org.apache.traffic_control.traffic_router.core.edge.InetRecordimport org.apache.traffic_control.traffic_router.core.edge.Node.IPVersionsimport org.apache.traffic_control.traffic_router.core.hash.DefaultHashableimport java.net.* org.apache.commons.lang3.builder.EqualsBuilderimport org.apache.logging.log4j.LogManager
import org.apache.traffic_control.traffic_router.core.edge.Nodeimport

org.apache.traffic_control.traffic_router.core.util.*import java.net.*
import java.util.ArrayList

import org.springframework.web.bind.annotation .RequestMapping
import org.springframework.beans.factory.annotation.Autowired
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
import java.util.Locale
import java.lang.IllegalArgumentException
import java.util.SortedSet
import java.util.TreeSet
import java.io.UnsupportedEncodingException
import java.lang.StringBuffer
import java.util.concurrent.atomic.AtomicInteger
import org.apache.traffic_control.traffic_router.core.ds.SteeringWatcher
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
import org.xbill.DNS.WireParseException
import org.apache.traffic_control.traffic_router.core.dns.protocol.UDP
import org.apache.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import org.xbill.DNS.OPTRecord
import java.lang.Runnable
import java.util.concurrent.ExecutorService
import org.apache.traffic_control.traffic_router.core.dns.NameServer
import org.apache.traffic_control.traffic_router.core.dns.DNSAccessRecord
import org.apache.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.lang.InterruptedException
import org.xbill.DNS.Rcode
import org.apache.traffic_control.traffic_router.core.dns.ZoneKey
import org.xbill.DNS.RRset
import org.apache.traffic_control.traffic_router.core.dns.RRsetKey
import java.text.SimpleDateFormat
import org.apache.traffic_control.traffic_router.core.dns.ZoneUtils
import java.util.Calendar
import java.lang.RuntimeException
import org.xbill.DNS.EDNSOption
import org.xbill.DNS.DClass
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.ClientSubnetOption
import org.apache.traffic_control.traffic_router.core.dns.ZoneManager
import org.xbill.DNS.SetResponse
import org.xbill.DNS.SOARecord
import org.apache.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import java.util.concurrent.ConcurrentMap
import org.apache.traffic_control.traffic_router.core.dns.RRSIGCacheKey
import org.xbill.DNS.RRSIGRecord
import org.xbill.DNS.DNSKEYRecord
import org.xbill.DNS.DSRecord
import org.apache.traffic_control.traffic_router.core.router.StatTracker
import org.apache.traffic_control.traffic_router.core.edge.CacheRegister
import org.apache.traffic_control.traffic_router.core.dns.SignatureManager
import org.apache.traffic_control.traffic_router.core.router.DNSRouteResult
import org.xbill.DNS.ARecord
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.TextParseException
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
import org.xbill.DNS.NSECRecord
import org.xbill.DNS.CNAMERecord
import org.xbill.DNS.TXTRecord
import org.xbill.DNS.NSRecord
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
import org.xbill.DNS.DNSSEC
import org.xbill.DNS.DNSSEC.DNSSECException
import org.apache.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import java.util.function.BiFunction
import java.util.function.ToIntFunction
import org.apache.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import java.util.function.BinaryOperator
import org.apache.traffic_control.traffic_router.secure.BindPrivateKey
import java.io.ByteArrayInputStream
import org.xbill.DNS.Master
import java.text.DecimalFormat
import java.math.RoundingMode
import org.apache.traffic_control.traffic_router.core.loc.FederationMapping
import org.apache.traffic_control.traffic_router.core.loc.Federation
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
import org.apache.traffic_control.traffic_router.core.edge.PropertiesAndCaches
import javax.crypto.SecretKeyFactory
import javax.crypto.SecretKey
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.PBEParameterSpec
import org.apache.traffic_control.traffic_router.core.config.WatcherConfig
import java.io.FileReader
import org.asynchttpclient.AsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClientConfig
import org.asynchttpclient.AsyncCompletionHandler
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
import java.lang.Void
import org.apache.traffic_control.traffic_router.core.router.StatelessTrafficRouterTest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.apache.traffic_control.traffic_router.secure.Pkcs1
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import org.mockito.Mock
import org.mockito.InjectMocks
import org.mockito.MockitoAnnotations
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

open class Node : DefaultHashable {
    enum class IPVersions {
        IPV4ONLY, IPV6ONLY, ANY
    }

    protected val id: String?
    private var fqdn: String? = null
    private var ipAddresses: MutableList<InetRecord?>? = null
    private var ip4: InetAddress? = null
    private var ip6: InetAddress? = null
    private var isAvailable = false
    private var ipv4Available = true
    private var ipv6Available = true
    private var hasAuthority = false
    private var port = 0
    private val deliveryServices: MutableMap<String?, DeliveryServiceReference?>? = HashMap()
    private val capabilities: MutableSet<String?>? = HashSet()
    private var httpsPort = 443

    constructor(id: String?) {
        this.id = id
        generateHashes(id, Node.Companion.REPLICAS)
    }

    // alternate constructor
    constructor(id: String?, hashId: String?, hashCount: Int) {
        this.id = id
        generateHashes(hashId, if (hashCount > 0) hashCount else Node.Companion.REPLICAS)
    }

    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is Node) {
            val rhs = obj as Node?
            EqualsBuilder()
                    .append(getId(), rhs.getId())
                    .isEquals
        } else {
            false
        }
    }

    fun getFqdn(): String? {
        return fqdn
    }

    fun getId(): String? {
        return id
    }

    fun getIpAddresses(ttls: JsonNode?): MutableList<InetRecord?>? {
        return getIpAddresses(ttls, true)
    }

    fun getIpAddresses(ttls: JsonNode?, ip6RoutingEnabled: Boolean): MutableList<InetRecord?>? {
        if (ipAddresses == null) {
            return null
        }
        val ret: MutableList<InetRecord?> = ArrayList()
        for (ir in ipAddresses) {
            if (ir.isInet6() && !ip6RoutingEnabled) {
                continue
            }
            var ttl: Long = 0
            if (ttls == null) {
                ttl = -1
            } else if (ir.isInet6()) {
                ttl = optLong(ttls, "AAAA")
            } else {
                ttl = optLong(ttls, "A")
            }
            ret.add(InetRecord(ir.getAddress(), ttl))
        }
        return ret
    }

    fun getPort(): Int {
        return port
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
                .append(getId())
                .toHashCode()
    }

    fun addCapabilities(capabilities: MutableSet<String?>?) {
        this.capabilities.addAll(capabilities)
    }

    fun getCapabilities(): MutableSet<String?>? {
        return capabilities
    }

    open fun setDeliveryServices(deliveryServices: MutableCollection<DeliveryServiceReference?>?) {
        for (deliveryServiceReference in deliveryServices) {
            this.deliveryServices[deliveryServiceReference.getDeliveryServiceId()] = deliveryServiceReference
        }
    }

    open fun hasDeliveryService(deliveryServiceId: String?): Boolean {
        return deliveryServices.containsKey(deliveryServiceId)
    }

    fun setFqdn(fqdn: String?) {
        this.fqdn = fqdn
    }

    fun setIpAddresses(ipAddresses: MutableList<InetRecord?>?) {
        this.ipAddresses = ipAddresses
    }

    fun setPort(port: Int) {
        this.port = port
    }

    override fun toString(): String {
        return "Node [id=$id] "
    }

    fun setIsAvailable(isAvailable: Boolean) {
        hasAuthority = true
        this.isAvailable = isAvailable
    }

    fun hasAuthority(): Boolean {
        return hasAuthority
    }

    fun isAvailable(): Boolean {
        return isAvailable
    }

    fun isAvailable(requestVersion: IPVersions?): Boolean {
        return when (requestVersion) {
            IPVersions.IPV4ONLY -> isAvailable && ipv4Available
            IPVersions.IPV6ONLY -> isAvailable && ipv6Available
            else -> isAvailable
        }
    }

    @Throws(UnknownHostException::class)
    fun setIpAddress(ip: String?, ip6: String?, ttl: Long) {
        ipAddresses = ArrayList()
        if (ip != null && !ip.isEmpty()) {
            ip4 = InetAddress.getByName(ip)
            ipAddresses.add(InetRecord(ip4, ttl))
        } else {
            Node.Companion.LOGGER.error(getFqdn() + " - no IPv4 address configured!")
        }
        if (ip6 != null && !ip6.isEmpty()) {
            val ip6addr = ip6.replace("/.*".toRegex(), "")
            this.ip6 = Inet6Address.getByName(ip6addr)
            ipAddresses.add(InetRecord(this.ip6, ttl))
        } else {
            Node.Companion.LOGGER.error(getFqdn() + " - no IPv6 address configured!")
        }
    }

    fun getIp4(): InetAddress? {
        return ip4
    }

    fun getIp6(): InetAddress? {
        return ip6
    }

    fun setState(state: JsonNode?) {
        if (state == null) {
            Node.Companion.LOGGER.warn("got null health state for $fqdn. Setting it to unavailable!")
            isAvailable = false
            ipv4Available = false
            ipv6Available = false
        } else {
            isAvailable = JsonUtils.optBoolean(state, "isAvailable", true)
            ipv4Available = JsonUtils.optBoolean(state, "ipv4Available", true)
            ipv6Available = JsonUtils.optBoolean(state, "ipv6Available", true)
        }
        setIsAvailable(isAvailable)
    }

    fun getHttpsPort(): Int {
        return httpsPort
    }

    fun setHttpsPort(httpsPort: Int) {
        this.httpsPort = httpsPort
    }

    companion object {
        private val LOGGER = LogManager.getLogger(Node::class.java)
        private const val REPLICAS = 1000
    }
}