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

import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.getCoverageZoneCacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.selectCachesByCZ
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.consistentHashForCoverageZone
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.consistentHashForGeolocation
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.consistentHashDeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.buildPatternBasedHashString
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.buildPatternBasedHashStringDeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.consistentHashSteeringForCoverageZone
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.cacheRegister
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.getZone
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.isDnssecZoneDiffingEnabled
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.isEdgeHTTPRouting
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.selectTrafficRoutersMiss
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.selectTrafficRoutersLocalized
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.isConsistentDNSRouting
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.inetRecordsFromCaches
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.isEdgeDNSRouting
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.route
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.anonymousIpDatabaseService
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.getClientGeolocation
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.requestHeaders
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.getLocation
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.getDeepCoverageZoneLocationByIP
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.zoneManager
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.configurationChanged
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.setState
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.setSteeringRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter.setApplicationContext
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
import com.comcast.cdn.traffic_control.traffic_router.core.router.RouteResult
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ContextRefreshedEvent
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesResponse
import com.comcast.cdn.traffic_control.traffic_router.configuration.ConfigurationListener
import org.springframework.core.env.Environment
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import org.springframework.context.event.ApplicationContextEvent
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorResourceUrl
import org.springframework.context.event.ContextClosedEvent
import java.security.spec.KeySpec
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1KeySpecDecoder
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs8
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1SequenceParser
import org.bouncycastle.asn1.ASN1Integer
import java.security.spec.RSAPublicKeySpec
import com.comcast.cdn.traffic_control.traffic_router.shared.SigningData
import java.security.KeyPairGenerator
import com.comcast.cdn.traffic_control.traffic_router.shared.ZoneTestRecords
import com.comcast.cdn.traffic_control.traffic_router.shared.IsEqualCollection
import javax.management.NotificationBroadcasterSupport
import javax.management.AttributeChangeNotification
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import org.junit.runner.RunWith
import org.powermock.modules.junit4.PowerMockRunner
import org.powermock.core.classloader.annotations.PrepareForTest
import org.junit.Before
import sun.security.rsa.RSAPrivateCrtKeyImpl
import org.powermock.api.mockito.PowerMockito
import java.lang.System
import com.comcast.cdn.traffic_control.traffic_router.utils.HttpsProperties
import java.nio.file.Paths
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509KeyManager
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateRegistry
import java.security.Principal
import java.lang.UnsupportedOperationException
import javax.net.ssl.SSLEngine
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIServerName
import com.comcast.cdn.traffic_control.traffic_router.secure.HandshakeData
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDecoder
import com.comcast.cdn.traffic_control.traffic_router.secure.CertificateDataConverter
import kotlin.jvm.Volatile
import com.comcast.cdn.traffic_control.traffic_router.protocol.RouterNioEndpoint
import java.security.KeyStore
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
import javax.management.MBeanServer
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
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.lang.Exception
import java.net.HttpURLConnection
import java.net.URL
import java.nio.file.Files
import java.util.*
import java.util.concurrent.ScheduledFuture

abstract class AbstractServiceUpdater constructor() {
    protected var dataBaseURL: String? = null
    protected var defaultDatabaseURL: String? = null
    protected var databaseName: String? = null
    protected var executorService: ScheduledExecutorService? = null
    private var pollingInterval: Long = 0
    protected var loaded: Boolean = false
    protected var scheduledService: ScheduledFuture<*>? = null
    private var trafficRouterManager: TrafficRouterManager? = null
    protected var databasesDirectory: Path? = null
    private var eTag: String? = null
    fun destroy() {
        executorService.shutdownNow()
    }

    /**
     * Gets dataBaseURL.
     *
     * @return the dataBaseURL
     */
    fun getDataBaseURL(): String? {
        return dataBaseURL
    }

    /**
     * Gets pollingInterval.
     *
     * @return the pollingInterval
     */
    fun getPollingInterval(): Long {
        if (pollingInterval == 0L) {
            return 10000
        }
        return pollingInterval
    }

    private val updater: Runnable? = object : Runnable {
        public override fun run() {
            try {
                updateDatabase()
            } catch (t: Throwable) {
                // Catching Throwable prevents this Service Updater thread from silently dying
                LOGGER.error("[" + javaClass.getSimpleName() + "] Failed updating database!", t)
            }
        }
    }

    fun init() {
        val pollingInterval: Long = getPollingInterval()
        val nextFetchDate: Date? = Date(System.currentTimeMillis() + pollingInterval)
        LOGGER.info("[" + javaClass.getSimpleName() + "] Fetching external resource " + dataBaseURL + " at interval: " + pollingInterval + " : " + TimeUnit.MILLISECONDS + " next update occurrs at " + nextFetchDate)
        scheduledService =
            executorService.scheduleWithFixedDelay(updater, pollingInterval, pollingInterval, TimeUnit.MILLISECONDS)
    }

    fun updateDatabase(): Boolean {
        try {
            if (!Files.exists(databasesDirectory)) {
                Files.createDirectories(databasesDirectory)
            }
        } catch (ex: IOException) {
            LOGGER.error(databasesDirectory.toString() + " does not exist and cannot be created!")
            return false
        }
        val existingDB: File? = databasesDirectory.resolve(databaseName).toFile()
        if (!isLoaded()) {
            try {
                setLoaded(loadDatabase())
            } catch (e: Exception) {
                LOGGER.warn("[" + javaClass.getSimpleName() + "] Failed to load existing database! " + e.message)
            }
        } else if (!needsUpdating(existingDB)) {
            LOGGER.info("[" + javaClass.getSimpleName() + "] Location database does not require updating.")
            return false
        }
        var newDB: File? = null
        var isModified: Boolean = true
        val databaseURL: String? = getDataBaseURL()
        if (databaseURL == null) {
            LOGGER.warn("[" + javaClass.getSimpleName() + "] Skipping download/update: database URL is null")
            return false
        }
        try {
            try {
                newDB = downloadDatabase(databaseURL, existingDB)
                trafficRouterManager.trackEvent("last" + javaClass.getSimpleName() + "Check")

                // if the remote db's timestamp is less than or equal to ours, the above returns existingDB
                if (newDB === existingDB) {
                    isModified = false
                }
            } catch (e: Exception) {
                LOGGER.fatal(
                    "[" + javaClass.getSimpleName() + "] Caught exception while attempting to download: " + getDataBaseURL(),
                    e
                )
                return false
            }
            if (!isModified || (newDB == null) || !newDB.exists()) {
                return false
            }
            try {
                if (!verifyDatabase(newDB)) {
                    LOGGER.warn("[" + javaClass.getSimpleName() + "] " + newDB.getAbsolutePath() + " from " + getDataBaseURL() + " is invalid!")
                    return false
                }
            } catch (e: Exception) {
                LOGGER.error("[" + javaClass.getSimpleName() + "] Failed verifying database " + newDB.getAbsolutePath() + " : " + e.message)
                return false
            }
            try {
                if (copyDatabaseIfDifferent(existingDB, newDB)) {
                    setLoaded(loadDatabase())
                    trafficRouterManager.trackEvent("last" + javaClass.getSimpleName() + "Update")
                } else {
                    newDB.delete()
                }
            } catch (e: Exception) {
                LOGGER.error("[" + javaClass.getSimpleName() + "] Failed copying and loading new database " + newDB.getAbsolutePath() + " : " + e.message)
            }
        } finally {
            if ((newDB != null) && (newDB !== existingDB) && newDB.exists()) {
                LOGGER.info("[" + javaClass.getSimpleName() + "] Try to delete downloaded temp file")
                deleteDatabase(newDB)
            }
        }
        return true
    }

    @Throws(IOException::class, JsonUtilsException::class)
    abstract fun verifyDatabase(dbFile: File?): Boolean
    @Throws(IOException::class, JsonUtilsException::class)
    abstract fun loadDatabase(): Boolean
    fun setDatabaseName(databaseName: String?) {
        this.databaseName = databaseName
    }

    fun stopServiceUpdater() {
        if (scheduledService != null) {
            LOGGER.info("[" + javaClass.getSimpleName() + "] Stopping service updater")
            scheduledService.cancel(false)
        }
    }

    fun cancelServiceUpdater() {
        stopServiceUpdater()
        pollingInterval = 0
        dataBaseURL = null
    }

    fun setDataBaseURL(url: String?, refresh: Long) {
        if (refresh != 0L && refresh != pollingInterval) {
            pollingInterval = refresh
            LOGGER.info("[" + javaClass.getSimpleName() + "] Restarting schedule for " + url + " with interval: " + refresh)
            stopServiceUpdater()
            init()
        }
        if ((url != null) && !(url == dataBaseURL) || (refresh != 0L && refresh != pollingInterval)) {
            dataBaseURL = url
            setLoaded(false)
            Thread(updater).start()
        }
    }

    fun setDatabaseUrl(url: String?) {
        dataBaseURL = url
    }

    fun setDefaultDatabaseUrl(url: String?) {
        defaultDatabaseURL = url
    }

    /**
     * Sets executorService.
     *
     * @param executorService
     * the executorService to set
     */
    fun setExecutorService(executorService: ScheduledExecutorService?) {
        this.executorService = executorService
    }

    /**
     * Sets pollingInterval.
     *
     * @param pollingInterval
     * the pollingInterval to set
     */
    fun setPollingInterval(pollingInterval: Long) {
        this.pollingInterval = pollingInterval
    }

    @Throws(IOException::class)
    fun filesEqual(a: File?, b: File?): Boolean {
        if (!a.exists() && !b.exists()) {
            return true
        }
        if (!a.exists() || !b.exists()) {
            return false
        }
        if (a.isDirectory() && b.isDirectory()) {
            return compareDirectories(a, b)
        }
        return compareFiles(a, b)
    }

    @Throws(IOException::class)
    private fun compareDirectories(a: File?, b: File?): Boolean {
        val aFileList: Array<File?>? = a.listFiles()
        val bFileList: Array<File?>? = b.listFiles()
        if (aFileList.size != bFileList.size) {
            return false
        }
        Arrays.sort(aFileList)
        Arrays.sort(bFileList)
        for (i in aFileList.indices) {
            if (aFileList.get(i).length() != bFileList.get(i).length()) {
                return false
            }
        }
        return true
    }

    @Throws(IOException::class)
    private fun fileMd5(file: File?): String? {
        FileInputStream(file).use({ stream -> return DigestUtils.md5Hex(stream) })
    }

    @Throws(IOException::class)
    private fun compareFiles(a: File?, b: File?): Boolean {
        if (a.length() != b.length()) {
            return false
        }
        return (fileMd5(a) == fileMd5(b))
    }

    @Throws(IOException::class)
    protected fun copyDatabaseIfDifferent(existingDB: File?, newDB: File?): Boolean {
        if (filesEqual(existingDB, newDB)) {
            LOGGER.info("[" + javaClass.getSimpleName() + "] database unchanged.")
            existingDB.setLastModified(newDB.lastModified())
            return false
        }
        if (existingDB.isDirectory() && newDB.isDirectory()) {
            moveDirectory(existingDB, newDB)
            LOGGER.info("[" + javaClass.getSimpleName() + "] Successfully updated database " + existingDB)
            return true
        }
        if (existingDB != null && existingDB.exists()) {
            deleteDatabase(existingDB)
        }
        newDB.setReadable(true, true)
        newDB.setWritable(true, false)
        val renamed: Boolean = newDB.renameTo(existingDB)
        if (!renamed) {
            LOGGER.fatal(
                "[" + javaClass.getSimpleName() + "] Unable to rename " + newDB + " to " + existingDB.getAbsolutePath() + "; current working directory is " + System.getProperty(
                    "user.dir"
                )
            )
            return false
        }
        LOGGER.info("[" + javaClass.getSimpleName() + "] Successfully updated database " + existingDB)
        return true
    }

    @Throws(IOException::class)
    private fun moveDirectory(existingDB: File?, newDB: File?) {
        LOGGER.info("[" + javaClass.getSimpleName() + "] Moving Location database from: " + newDB + ", to: " + existingDB)
        for (file: File? in existingDB.listFiles()) {
            file.setReadable(true, true)
            file.setWritable(true, false)
            file.delete()
        }
        existingDB.delete()
        Files.move(newDB.toPath(), existingDB.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private fun deleteDatabase(db: File?) {
        db.setReadable(true, true)
        db.setWritable(true, false)
        if (db.isDirectory()) {
            for (file: File? in db.listFiles()) {
                file.delete()
            }
            LOGGER.debug("[" + javaClass.getSimpleName() + "] Successfully deleted database under: " + db)
        } else {
            db.delete()
        }
    }

    protected var sourceCompressed: Boolean = true
    protected var tmpPrefix: String? = "loc"
    protected var tmpSuffix: String? = ".dat"
    @Throws(IOException::class)
    protected open fun downloadDatabase(url: String?, existingDb: File?): File? {
        LOGGER.info("[" + javaClass.getSimpleName() + "] Downloading database: " + url)
        val dbURL: URL? = URL(url)
        val conn: HttpURLConnection? = dbURL.openConnection() as HttpURLConnection?
        if (useModifiedTimestamp(existingDb)) {
            conn.setIfModifiedSince(existingDb.lastModified())
            if (eTag != null) {
                conn.setRequestProperty("If-None-Match", eTag)
            }
        }
        var `in`: InputStream? = conn.getInputStream()
        eTag = conn.getHeaderField("ETag")
        if (conn.getResponseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
            LOGGER.info(
                "[" + javaClass.getSimpleName() + "] " + url + " not modified since our existing database's last update time of " + Date(
                    existingDb.lastModified()
                )
            )
            return existingDb
        }
        if (sourceCompressed) {
            `in` = GZIPInputStream(`in`)
        }
        val outputFile: File? = File.createTempFile(tmpPrefix, tmpSuffix)
        val out: OutputStream? = FileOutputStream(outputFile)
        IOUtils.copy(`in`, out)
        IOUtils.closeQuietly(`in`)
        IOUtils.closeQuietly(out)
        return outputFile
    }

    private fun useModifiedTimestamp(existingDb: File?): Boolean {
        return (existingDb != null) && existingDb.exists() && (existingDb.lastModified() > 0
                ) && (!existingDb.isDirectory() || existingDb.listFiles().size > 0)
    }

    protected fun needsUpdating(existingDB: File?): Boolean {
        val now: Long = System.currentTimeMillis()
        val fileTime: Long = existingDB.lastModified()
        val pollingIntervalInMS: Long = getPollingInterval()
        return ((fileTime + pollingIntervalInMS) < now)
    }

    fun setLoaded(loaded: Boolean) {
        this.loaded = loaded
    }

    open fun isLoaded(): Boolean {
        return loaded
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun getDatabasesDirectory(): Path? {
        return databasesDirectory
    }

    fun setDatabasesDirectory(databasesDirectory: Path?) {
        this.databasesDirectory = databasesDirectory
    }

    companion object {
        private val LOGGER: Logger? = Logger.getLogger(AbstractServiceUpdater::class.java)
    }
}