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
package org.apache.traffic_control.traffic_router.core.dnsimportimportimport

com.fasterxml.jackson.databind.JsonNodeimport com.fasterxml.jackson.databind.ObjectMapperimport org.apache.traffic_control.traffic_router.core.dns.*import org.apache.traffic_control.traffic_router.core.dns.ZoneManager.ZoneCacheTypeimport

org.apache.traffic_control.traffic_router.core.edge.CacheRegisterimport org.apache.traffic_control.traffic_router.core.router.TrafficRouterimport org.apache.traffic_control.traffic_router.core.router.TrafficRouterManagerimport org.xbill.DNS.*import java.io.IOExceptionimport

java.security.GeneralSecurityExceptionimport java.security.NoSuchAlgorithmExceptionimport java.util.concurrent.*import java.util.function.BinaryOperator

org.apache.logging.log4j.LogManagerimport org.apache.traffic_control.traffic_router.core.util.*
import org.xbill.DNS.*
import org.xbill.DNS.Recordimport

java.util.*import java.util.concurrent.*
import java.util.function.BiConsumerimport

java.util.function.Consumerimport java.util.function.Function org.springframework.web.bind.annotation .RequestMapping
import org.springframework.beans.factory.annotation.Autowired
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
import java.net.URLDecoder
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
import java.lang.IllegalArgumentException
import java.io.UnsupportedEncodingException
import java.lang.StringBuffer
import java.util.concurrent.atomic.AtomicInteger
import org.apache.traffic_control.traffic_router.core.ds.SteeringWatcher
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
import java.net.ServerSocket
import org.apache.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import org.apache.traffic_control.traffic_router.core.dns.protocol.TCP
import java.io.DataInputStream
import java.net.DatagramSocket
import org.apache.traffic_control.traffic_router.core.dns.protocol.UDP
import org.apache.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import java.lang.Runnable
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
import org.apache.traffic_control.traffic_router.core.dns.RRSIGCacheKey
import org.apache.traffic_control.traffic_router.core.router.StatTracker
import org.apache.traffic_control.traffic_router.core.edge.CacheRegister
import org.apache.traffic_control.traffic_router.core.dns.SignatureManager
import org.apache.traffic_control.traffic_router.core.router.DNSRouteResult
import java.net.Inet6Address
import org.apache.traffic_control.traffic_router.core.dns.ZoneManager.ZoneCacheType
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
import org.apache.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import java.util.function.BinaryOperator
import org.apache.traffic_control.traffic_router.secure.BindPrivateKey
import java.io.ByteArrayInputStream
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
import java.net.Inet4Address
import org.apache.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import org.apache.traffic_control.traffic_router.core.hash.Hashable
import org.apache.traffic_control.traffic_router.core.hash.NumberSearcher
import org.apache.traffic_control.traffic_router.core.hash.MD5HashFunction
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
import java.net.URISyntaxException
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
import java.net.SocketTimeoutException
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

class SignatureManager(zoneManager: ZoneManager?, cacheRegister: CacheRegister?, trafficOpsUtils: TrafficOpsUtils?, private val trafficRouterManager: TrafficRouterManager?) {
    private var expirationMultiplier = 0
    private var cacheRegister: CacheRegister? = null
    private var RRSIGCacheEnabled = false
    private var trafficOpsUtils: TrafficOpsUtils? = null
    private var dnssecEnabled = false
    private var expiredKeyAllowed = true
    private var keyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>? = null
    private var fetcher: ProtectedFetcher? = null
    private var zoneManager: ZoneManager? = null

    init {
        setCacheRegister(cacheRegister)
        setTrafficOpsUtils(trafficOpsUtils)
        setZoneManager(zoneManager)
        setRRSIGCacheEnabled(cacheRegister.getConfig())
        initKeyMap()
    }

    fun destroy() {
        if (SignatureManager.Companion.keyMaintenanceExecutor != null) {
            SignatureManager.Companion.keyMaintenanceExecutor.shutdownNow()
        }
    }

    private fun setRRSIGCacheEnabled(config: JsonNode?) {
        RRSIGCacheEnabled = JsonUtils.optBoolean(config, TrafficRouter.Companion.DNSSEC_RRSIG_CACHE_ENABLED, false)
        if (!RRSIGCacheEnabled) {
            synchronized(SignatureManager.Companion.RRSIGCacheLock) { SignatureManager.Companion.RRSIGCache = ConcurrentHashMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>() }
        }
    }

    private fun isRRSIGCacheEnabled(): Boolean {
        return RRSIGCacheEnabled
    }

    private fun initKeyMap() {
        synchronized(SignatureManager::class.java) {
            val config = cacheRegister.getConfig()
            val dnssecEnabled: Boolean = optBoolean(config, TrafficRouter.Companion.DNSSEC_ENABLED)
            if (dnssecEnabled) {
                setDnssecEnabled(true)
                setExpiredKeyAllowed(JsonUtils.optBoolean(config, "dnssec.allow.expired.keys", true)) // allowing this by default is the safest option
                setExpirationMultiplier(JsonUtils.optInt(config, "signaturemanager.expiration.multiplier", 5)) // signature validity is maxTTL * this
                val me = Executors.newScheduledThreadPool(1)
                val maintenanceInterval = JsonUtils.optInt(config, "keystore.maintenance.interval", 300) // default 300 seconds, do we calculate based on the complimentary settings for key generation in TO?
                me.scheduleWithFixedDelay(getKeyMaintenanceRunnable(cacheRegister), 0, maintenanceInterval.toLong(), TimeUnit.SECONDS)
                if (SignatureManager.Companion.keyMaintenanceExecutor != null) {
                    SignatureManager.Companion.keyMaintenanceExecutor.shutdownNow()
                }
                SignatureManager.Companion.keyMaintenanceExecutor = me
                try {
                    while (keyMap == null) {
                        SignatureManager.Companion.LOGGER.info("Waiting for DNSSEC keyMap initialization to complete")
                        Thread.sleep(2000)
                    }
                } catch (e: InterruptedException) {
                    SignatureManager.Companion.LOGGER.fatal(e, e)
                }
            } else {
                SignatureManager.Companion.LOGGER.info("DNSSEC not enabled; to enable, activate DNSSEC for this Traffic Router's CDN in Traffic Ops")
            }
        }
    }

    private fun getKeyMaintenanceRunnable(cacheRegister: CacheRegister?): Runnable? {
        return Runnable {
            try {
                trafficRouterManager.trackEvent("lastDnsSecKeysCheck")
                val newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?> = HashMap()
                val keyPairData = fetchKeyPairData(cacheRegister)
                if (keyPairData != null) {
                    val response = JsonUtils.getJsonNode(keyPairData, "response")
                    val dsIt: MutableIterator<*>? = response.fieldNames()
                    val config = cacheRegister.getConfig()
                    val defaultTTL = ZoneUtils.getLong(config["ttls"], "DNSKEY", 60)
                    while (dsIt.hasNext()) {
                        val keyTypes = JsonUtils.getJsonNode(response, dsIt.next() as String?)
                        val typeIt: MutableIterator<*>? = keyTypes.fieldNames()
                        while (typeIt.hasNext()) {
                            val keyPairs = JsonUtils.getJsonNode(keyTypes, typeIt.next() as String?)
                            if (keyPairs.isArray) {
                                for (keyPair in keyPairs) {
                                    try {
                                        val dkpw: DnsSecKeyPair = DnsSecKeyPairImpl(keyPair, defaultTTL)
                                        if (!newKeyMap.containsKey(dkpw.name)) {
                                            newKeyMap[dkpw.name] = ArrayList()
                                        }
                                        val keyList = newKeyMap[dkpw.name]
                                        keyList.add(dkpw)
                                        newKeyMap[dkpw.name] = keyList
                                        SignatureManager.Companion.LOGGER.debug("Added $dkpw to incoming keyList")
                                    } catch (ex: JsonUtilsException) {
                                        SignatureManager.Companion.LOGGER.fatal("JsonUtilsException caught while parsing key for $keyPair", ex)
                                    } catch (ex: TextParseException) {
                                        SignatureManager.Companion.LOGGER.fatal(ex, ex)
                                    } catch (ex: IOException) {
                                        SignatureManager.Companion.LOGGER.fatal(ex, ex)
                                    }
                                }
                            }
                        }
                    }
                    cleanRRSIGCache(keyMap, newKeyMap)
                    if (keyMap == null) {
                        // initial startup
                        keyMap = newKeyMap
                    } else if (hasNewKeys(keyMap, newKeyMap)) {
                        // incoming key map has new keys
                        SignatureManager.Companion.LOGGER.debug("Found new keys in incoming keyMap; rebuilding zone caches")
                        trafficRouterManager.trackEvent("newDnsSecKeysFound")
                        keyMap = newKeyMap
                        getZoneManager().rebuildZoneCache()
                    } // no need to overwrite the keymap if they're the same, so no else leg
                } else {
                    SignatureManager.Companion.LOGGER.fatal("Unable to read keyPairData: $keyPairData")
                }
            } catch (ex: JsonUtilsException) {
                SignatureManager.Companion.LOGGER.fatal("JsonUtilsException caught while trying to maintain keyMap", ex)
            } catch (ex: RuntimeException) {
                SignatureManager.Companion.LOGGER.fatal("RuntimeException caught while trying to maintain keyMap", ex)
            }
        }
    }

    private fun cleanRRSIGCache(oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?, newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?) {
        synchronized(SignatureManager.Companion.RRSIGCacheLock) {
            if (SignatureManager.Companion.RRSIGCache.isEmpty() || oldKeyMap == null || getKeyDifferences(oldKeyMap, newKeyMap).isEmpty()) {
                return
            }
            val oldKeySize: Int = SignatureManager.Companion.RRSIGCache.size
            val oldRRSIGSize: Int = SignatureManager.Companion.RRSIGCache.values.stream().map<Int?>(Function { obj: ConcurrentMap<RRsetKey?, RRSIGRecord?>? -> obj.size }).reduce(0, BinaryOperator { a: Int, b: Int -> Integer.sum(a, b) })
            val now = Date().time
            val newRRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?> = ConcurrentHashMap()
            newKeyMap.forEach(BiConsumer { name: String?, keyPairs: MutableList<DnsSecKeyPair?>? ->
                keyPairs.forEach(Consumer { keypair: DnsSecKeyPair? ->
                    val cacheKey = RRSIGCacheKey(keypair.getPrivate().encoded, keypair.getDNSKEYRecord().algorithm)
                    val cacheValue: ConcurrentMap<RRsetKey?, RRSIGRecord?> = SignatureManager.Companion.RRSIGCache.get(cacheKey)
                    if (cacheValue != null) {
                        cacheValue.entries.removeIf { e: MutableMap.MutableEntry<RRsetKey?, RRSIGRecord?>? -> e.value.getExpire().time <= now }
                        newRRSIGCache[cacheKey] = cacheValue
                    }
                })
            })
            SignatureManager.Companion.RRSIGCache = newRRSIGCache
            val keySize: Int = SignatureManager.Companion.RRSIGCache.size
            val RRSIGSize: Int = SignatureManager.Companion.RRSIGCache.values.stream().map<Int?>(Function { obj: ConcurrentMap<RRsetKey?, RRSIGRecord?>? -> obj.size }).reduce(0, BinaryOperator { a: Int, b: Int -> Integer.sum(a, b) })
            SignatureManager.Companion.LOGGER.info("DNSSEC keys were changed or removed so RRSIG cache was cleaned. Old key size: " + oldKeySize +
                    ", new key size: " + keySize + ", old RRSIG size: " + oldRRSIGSize + ", new RRSIG size: " + RRSIGSize)
        }
    }

    // return the key names from newKeyMap that are different or missing from oldKeyMap
    private fun getKeyDifferences(newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?, oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?): MutableSet<String?>? {
        val newKeyNames: MutableSet<String?> = HashSet()
        for (newName in newKeyMap.keys) {
            if (!oldKeyMap.containsKey(newName)) {
                newKeyNames.add(newName)
                continue
            }
            for (newKeyPair in newKeyMap.get(newName)) {
                var matched = false
                for (keyPair in oldKeyMap.get(newName)) {
                    if (newKeyPair == keyPair) {
                        matched = true
                        break
                    }
                }
                if (!matched) {
                    newKeyNames.add(newKeyPair.getName())
                    break
                }
            }
        }
        return newKeyNames
    }

    private fun hasNewKeys(oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?, newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?): Boolean {
        val newOrChangedKeyNames = getKeyDifferences(newKeyMap, oldKeyMap)
        if (!newOrChangedKeyNames.isEmpty()) {
            newOrChangedKeyNames.forEach(Consumer { name: String? -> SignatureManager.Companion.LOGGER.info("Found new or changed key for $name") })
            return true
        }
        return false
    }

    private fun fetchKeyPairData(cacheRegister: CacheRegister?): JsonNode? {
        if (!isDnssecEnabled()) {
            return null
        }
        var keyPairs: JsonNode? = null
        val mapper = ObjectMapper()
        try {
            val keyUrl = trafficOpsUtils.getUrl("keystore.api.url", "https://\${toHostname}/api/" + TrafficOpsUtils.Companion.TO_API_VERSION + "/cdns/name/\${cdnName}/dnsseckeys")
            val config = cacheRegister.getConfig()
            val timeout = JsonUtils.optInt(config, "keystore.fetch.timeout", 30000) // socket timeouts are in ms
            val retries = JsonUtils.optInt(config, "keystore.fetch.retries", 5)
            val wait = JsonUtils.optInt(config, "keystore.fetch.wait", 5000) // 5 seconds
            if (fetcher == null) {
                fetcher = ProtectedFetcher(trafficOpsUtils.getAuthUrl(), trafficOpsUtils.getAuthJSON().toString(), timeout)
            }
            for (i in 1..retries) {
                try {
                    val content = fetcher.fetch(keyUrl)
                    if (content != null) {
                        keyPairs = mapper.readTree(content)
                        break
                    }
                } catch (ex: IOException) {
                    SignatureManager.Companion.LOGGER.fatal(ex, ex)
                }
                try {
                    Thread.sleep(wait.toLong())
                } catch (ex: InterruptedException) {
                    SignatureManager.Companion.LOGGER.fatal(ex, ex)
                    // break if we're interrupted
                    break
                }
            }
        } catch (ex: IOException) {
            SignatureManager.Companion.LOGGER.fatal(ex, ex)
        }
        return keyPairs
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZoneSigningKSKPair(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getZoneSigningKeyPair(name, true, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZoneSigningZSKPair(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getZoneSigningKeyPair(name, false, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZoneSigningKeyPair(name: Name?, wantKsk: Boolean, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        /*
		 * This method returns a list, but we will identify the correct key with which to sign the zone.
		 * We select one key (we call this method twice, for zsk and ksks respectively)
		 * to follow the pre-publish key roll methodology described in RFC 6781.
		 * https://tools.ietf.org/html/rfc6781#section-4.1.1.1
		 */
        return getKeyPairs(name, wantKsk, true, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getKSKPairs(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getKeyPairs(name, true, false, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getZSKPairs(name: Name?, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        return getKeyPairs(name, false, false, maxTTL)
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun getKeyPairs(name: Name?, wantKsk: Boolean, wantSigningKey: Boolean, maxTTL: Long): MutableList<DnsSecKeyPair?>? {
        val keyPairs = keyMap.get(name.toString().lowercase(Locale.getDefault()))
        var signingKey: DnsSecKeyPair? = null
        if (keyPairs == null) {
            return null
        }
        val keys: MutableList<DnsSecKeyPair?> = ArrayList()
        for (kpw in keyPairs) {
            val kn = kpw.getDNSKEYRecord().name
            val isKsk = kpw.isKeySigningKey()
            if (kn == name) {
                if (isKsk && !wantKsk || !isKsk && wantKsk) {
                    SignatureManager.Companion.LOGGER.debug("Skipping key: wantKsk = " + wantKsk + "; key: " + kpw.toString())
                    continue
                } else if (!wantSigningKey && (isExpiredKeyAllowed() || kpw.isKeyCached(maxTTL))) {
                    SignatureManager.Companion.LOGGER.debug("key selected: " + kpw.toString())
                    keys.add(kpw)
                } else if (wantSigningKey) {
                    if (!kpw.isUsable()) { // effective date in the future
                        SignatureManager.Companion.LOGGER.debug("Skipping unusable signing key: " + kpw.toString())
                        continue
                    } else if (!isExpiredKeyAllowed() && kpw.isExpired()) {
                        SignatureManager.Companion.LOGGER.warn("Unable to use expired signing key: " + kpw.toString())
                        continue
                    }

                    // Locate the key with the earliest valid effective date accounting for expiration
                    if (isKsk && wantKsk || !isKsk && !wantKsk) {
                        if (signingKey == null) {
                            signingKey = kpw
                        } else if (signingKey.isExpired && !kpw.isExpired()) {
                            signingKey = kpw
                        } else if (signingKey.isExpired && kpw.isNewer(signingKey)) {
                            signingKey = kpw // if we have an expired key, try to find the most recent
                        } else if (!signingKey.isExpired && !kpw.isExpired() && kpw.isOlder(signingKey)) {
                            signingKey = kpw // otherwise use the oldest valid/non-expired key
                        }
                    }
                }
            } else {
                SignatureManager.Companion.LOGGER.warn("Invalid key for " + name + "; it is intended for " + kpw.toString())
            }
        }
        if (wantSigningKey && signingKey != null) {
            if (signingKey.isExpired) {
                SignatureManager.Companion.LOGGER.warn("Using expired signing key: $signingKey")
            } else {
                SignatureManager.Companion.LOGGER.debug("Signing key selected: $signingKey")
            }
            keys.clear() // in case we have something in here for some reason (shouldn't happen)
            keys.add(signingKey)
        } else if (wantSigningKey && signingKey == null) {
            SignatureManager.Companion.LOGGER.fatal("Unable to find signing key for $name")
        }
        return keys
    }

    private fun calculateKeyExpiration(keyPairs: MutableList<DnsSecKeyPair?>?): Calendar? {
        val expiration = Calendar.getInstance()
        var earliest: Date? = null
        for (keyPair in keyPairs) {
            if (earliest == null) {
                earliest = keyPair.getExpiration()
            } else if (keyPair.getExpiration().before(earliest)) {
                earliest = keyPair.getExpiration()
            }
        }
        expiration.time = earliest
        return expiration
    }

    private fun calculateSignatureExpiration(baseTimeInMillis: Long, records: MutableList<Record?>?): Calendar? {
        val expiration = Calendar.getInstance()
        val maxTTL = ZoneUtils.getMaximumTTL(records) * 1000 // convert TTL to millis
        val signatureExpiration = baseTimeInMillis + maxTTL * getExpirationMultiplier()
        expiration.timeInMillis = signatureExpiration
        return expiration
    }

    fun needsRefresh(type: ZoneCacheType?, zoneKey: ZoneKey?, refreshInterval: Int): Boolean {
        return if (zoneKey is SignedZoneKey) {
            val szk = zoneKey as SignedZoneKey?
            val now = System.currentTimeMillis()
            val nextRefresh = now + refreshInterval * 1000 // refreshInterval is in seconds, convert to millis
            if (nextRefresh >= szk.getRefreshHorizon()) {
                SignatureManager.Companion.LOGGER.info(getRefreshMessage(type, szk, true, "refresh horizon approaching"))
                true
            } else if (!isExpiredKeyAllowed() && now >= szk.getEarliestSigningKeyExpiration()) {
                /*
				 * The earliest signing key has expired, so force a resigning
				 * which will be done with new keys. This is because the keys themselves
				 * don't have expiry that's tied to DNSSEC; it's administrative, so
				 * we can be a little late on the swap.
				 */
                SignatureManager.Companion.LOGGER.info(getRefreshMessage(type, szk, true, "signing key expiration"))
                true
            } else {
                SignatureManager.Companion.LOGGER.debug(getRefreshMessage(type, szk))
                false
            }
        } else {
            SignatureManager.Companion.LOGGER.debug(type.toString() + ": " + zoneKey.getName() + " is not a signed zone; no refresh needed")
            false
        }
    }

    private fun getRefreshMessage(type: ZoneCacheType?, zoneKey: SignedZoneKey?): String? {
        return getRefreshMessage(type, zoneKey, false, null)
    }

    private fun getRefreshMessage(type: ZoneCacheType?, zoneKey: SignedZoneKey?, needsRefresh: Boolean, message: String?): String? {
        val sb = StringBuilder()
        sb.append(type)
        sb.append(": timestamp for ")
        sb.append(zoneKey.getName())
        sb.append(" is ")
        sb.append(zoneKey.getTimestampDate())
        sb.append("; expires ")
        sb.append(zoneKey.getMinimumSignatureExpiration().time)
        if (needsRefresh) {
            sb.append("; refresh needed")
        } else {
            sb.append("; no refresh needed")
        }
        if (message != null) {
            sb.append("; ")
            sb.append(message)
        }
        return sb.toString()
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun signZone(name: Name?, records: MutableList<Record?>?, zoneKey: SignedZoneKey?): MutableList<Record?>? {
        val maxTTL = ZoneUtils.getMaximumTTL(records)
        val kskPairs = getZoneSigningKSKPair(name, maxTTL)
        val zskPairs = getZoneSigningZSKPair(name, maxTTL)

        // TODO: do we really need to fully sign the apex keyset? should the digest be config driven?
        if (kskPairs != null && zskPairs != null) {
            if (!kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                val signatureExpiration = calculateSignatureExpiration(zoneKey.getTimestamp(), records)
                val kskExpiration = calculateKeyExpiration(kskPairs)
                val zskExpiration = calculateKeyExpiration(zskPairs)
                val now = System.currentTimeMillis()
                val start = Calendar.getInstance()
                start.timeInMillis = now
                start.add(Calendar.HOUR, -1)
                SignatureManager.Companion.LOGGER.info("Signing zone " + name + " with start " + start.time + " and expiration " + signatureExpiration.getTime())
                val signedRecords: MutableList<Record?>
                val zoneSigner: ZoneSigner = ZoneSignerImpl()
                signedRecords = zoneSigner.signZone(records, kskPairs, zskPairs, start.time,
                        signatureExpiration.getTime(), if (isRRSIGCacheEnabled()) SignatureManager.Companion.RRSIGCache else null)
                zoneKey.setMinimumSignatureExpiration(signedRecords, signatureExpiration)
                zoneKey.setKSKExpiration(kskExpiration)
                zoneKey.setZSKExpiration(zskExpiration)
                return signedRecords
            } else {
                SignatureManager.Companion.LOGGER.warn("Unable to sign zone " + name + "; have " + kskPairs.size + " KSKs and " + zskPairs.size + " ZSKs")
            }
        } else {
            SignatureManager.Companion.LOGGER.warn("Unable to sign zone $name; ksks or zsks are null")
        }
        return records
    }

    @Throws(NoSuchAlgorithmException::class, IOException::class)
    fun generateDSRecords(name: Name?, maxTTL: Long): MutableList<Record?>? {
        val records: MutableList<Record?> = ArrayList()
        if (isDnssecEnabled() && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            val config = getCacheRegister().getConfig()
            val kskPairs = getKSKPairs(name, maxTTL)
            val zskPairs = getZSKPairs(name, maxTTL)
            if (kskPairs != null && zskPairs != null && !kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                // these records go into the CDN TLD, so don't use the DS' TTLs; use the CDN's.
                val dsTtl = ZoneUtils.getLong(config["ttls"], "DS", 60)
                for (kp in kskPairs) {
                    val zoneSigner: ZoneSigner = ZoneSignerImpl()
                    val dsRecord = zoneSigner.calculateDSRecord(kp.getDNSKEYRecord(), DSRecord.SHA256_DIGEST_ID, dsTtl)
                    SignatureManager.Companion.LOGGER.debug(name.toString() + ": adding DS record " + dsRecord)
                    records.add(dsRecord)
                }
            }
        }
        return records
    }

    @Throws(NoSuchAlgorithmException::class, IOException::class)
    fun generateDNSKEYRecords(name: Name?, maxTTL: Long): MutableList<Record?>? {
        val list: MutableList<Record?> = ArrayList()
        if (isDnssecEnabled() && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            val kskPairs = getKSKPairs(name, maxTTL)
            val zskPairs = getZSKPairs(name, maxTTL)
            if (kskPairs != null && zskPairs != null && !kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                for (kp in kskPairs) {
                    SignatureManager.Companion.LOGGER.debug(name.toString() + ": DNSKEY record " + kp.getDNSKEYRecord())
                    list.add(kp.getDNSKEYRecord())
                }
                for (kp in zskPairs) {
                    // TODO: make adding zsk to parent zone configurable?
                    SignatureManager.Companion.LOGGER.debug(name.toString() + ": DNSKEY record " + kp.getDNSKEYRecord())
                    list.add(kp.getDNSKEYRecord())
                }
            }
        }
        return list
    }

    // this method is called during static zone generation
    fun generateZoneKey(name: Name?, list: MutableList<Record?>?): ZoneKey? {
        return generateZoneKey(name, list, false, false)
    }

    fun generateDynamicZoneKey(name: Name?, list: MutableList<Record?>?, dnssecRequest: Boolean): ZoneKey? {
        return generateZoneKey(name, list, true, dnssecRequest)
    }

    private fun generateZoneKey(name: Name?, list: MutableList<Record?>?, dynamicRequest: Boolean, dnssecRequest: Boolean): ZoneKey? {
        return if (dynamicRequest && !dnssecRequest) {
            ZoneKey(name, list)
        } else if (isDnssecEnabled(name) && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            SignedZoneKey(name, list)
        } else {
            ZoneKey(name, list)
        }
    }

    fun isDnssecEnabled(): Boolean {
        return dnssecEnabled
    }

    private fun isDnssecEnabled(name: Name?): Boolean {
        return dnssecEnabled && keyMap.containsKey(name.toString().lowercase(Locale.getDefault()))
    }

    private fun setDnssecEnabled(dnssecEnabled: Boolean) {
        this.dnssecEnabled = dnssecEnabled
    }

    protected fun getCacheRegister(): CacheRegister? {
        return cacheRegister
    }

    private fun setCacheRegister(cacheRegister: CacheRegister?) {
        this.cacheRegister = cacheRegister
    }

    fun getExpirationMultiplier(): Int {
        return expirationMultiplier
    }

    fun setExpirationMultiplier(expirationMultiplier: Int) {
        this.expirationMultiplier = expirationMultiplier
    }

    private fun getZoneManager(): ZoneManager? {
        return zoneManager
    }

    private fun setZoneManager(zoneManager: ZoneManager?) {
        this.zoneManager = zoneManager
    }

    private fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    fun isExpiredKeyAllowed(): Boolean {
        return expiredKeyAllowed
    }

    fun setExpiredKeyAllowed(expiredKeyAllowed: Boolean) {
        this.expiredKeyAllowed = expiredKeyAllowed
    }

    companion object {
        private val LOGGER = LogManager.getLogger(SignatureManager::class.java)
        private val RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>? = ConcurrentHashMap()
        private val RRSIGCacheLock: Any? = Any() // to ensure that the RRSIGCache is totally empty if disabled
        private val keyMaintenanceExecutor: ScheduledExecutorService? = null
    }
}