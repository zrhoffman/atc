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
package com.comcast.cdn.traffic_control.traffic_router.core.dns

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
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import java.util.*
import java.util.function.Consumer
import java.util.function.Function
import java.util.function.Predicate

class SignatureManager constructor(
    zoneManager: ZoneManager?,
    cacheRegister: CacheRegister?,
    trafficOpsUtils: TrafficOpsUtils?,
    private val trafficRouterManager: TrafficRouterManager?
) {
    private var expirationMultiplier: Int = 0
    private var cacheRegister: CacheRegister? = null
    private var RRSIGCacheEnabled: Boolean = false
    private var trafficOpsUtils: TrafficOpsUtils? = null
    private var dnssecEnabled: Boolean = false
    private var expiredKeyAllowed: Boolean = true
    private var keyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>? = null
    private var fetcher: ProtectedFetcher? = null
    private var zoneManager: ZoneManager? = null
    fun destroy() {
        if (keyMaintenanceExecutor != null) {
            keyMaintenanceExecutor.shutdownNow()
        }
    }

    private fun setRRSIGCacheEnabled(config: JsonNode?) {
        RRSIGCacheEnabled = JsonUtils.optBoolean(config, TrafficRouter.DNSSEC_RRSIG_CACHE_ENABLED, false)
        if (!RRSIGCacheEnabled) {
            synchronized(RRSIGCacheLock, { RRSIGCache = ConcurrentHashMap() })
        }
    }

    private fun isRRSIGCacheEnabled(): Boolean {
        return RRSIGCacheEnabled
    }

    private fun initKeyMap() {
        synchronized(SignatureManager::class.java, {
            val config: JsonNode? = cacheRegister.getConfig()
            val dnssecEnabled: Boolean = optBoolean(config, TrafficRouter.DNSSEC_ENABLED)
            if (dnssecEnabled) {
                setDnssecEnabled(true)
                setExpiredKeyAllowed(
                    JsonUtils.optBoolean(
                        config,
                        "dnssec.allow.expired.keys",
                        true
                    )
                ) // allowing this by default is the safest option
                setExpirationMultiplier(
                    JsonUtils.optInt(
                        config,
                        "signaturemanager.expiration.multiplier",
                        5
                    )
                ) // signature validity is maxTTL * this
                val me: ScheduledExecutorService? = Executors.newScheduledThreadPool(1)
                val maintenanceInterval: Int = JsonUtils.optInt(
                    config,
                    "keystore.maintenance.interval",
                    300
                ) // default 300 seconds, do we calculate based on the complimentary settings for key generation in TO?
                me.scheduleWithFixedDelay(
                    getKeyMaintenanceRunnable(cacheRegister),
                    0,
                    maintenanceInterval.toLong(),
                    TimeUnit.SECONDS
                )
                if (keyMaintenanceExecutor != null) {
                    keyMaintenanceExecutor.shutdownNow()
                }
                keyMaintenanceExecutor = me
                try {
                    while (keyMap == null) {
                        LOGGER.info("Waiting for DNSSEC keyMap initialization to complete")
                        Thread.sleep(2000)
                    }
                } catch (e: InterruptedException) {
                    LOGGER.fatal(e, e)
                }
            } else {
                LOGGER.info("DNSSEC not enabled; to enable, activate DNSSEC for this Traffic Router's CDN in Traffic Ops")
            }
        })
    }

    private fun getKeyMaintenanceRunnable(cacheRegister: CacheRegister?): Runnable? {
        return object : Runnable {
            public override fun run() {
                try {
                    trafficRouterManager.trackEvent("lastDnsSecKeysCheck")
                    val newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>? = HashMap()
                    val keyPairData: JsonNode? = fetchKeyPairData(cacheRegister)
                    if (keyPairData != null) {
                        val response: JsonNode? = JsonUtils.getJsonNode(keyPairData, "response")
                        val dsIt: MutableIterator<*>? = response.fieldNames()
                        val config: JsonNode? = cacheRegister.getConfig()
                        val defaultTTL: Long = ZoneUtils.getLong(config.get("ttls"), "DNSKEY", 60)
                        while (dsIt.hasNext()) {
                            val keyTypes: JsonNode? = JsonUtils.getJsonNode(response, dsIt.next() as String?)
                            val typeIt: MutableIterator<*>? = keyTypes.fieldNames()
                            while (typeIt.hasNext()) {
                                val keyPairs: JsonNode? = JsonUtils.getJsonNode(keyTypes, typeIt.next() as String?)
                                if (keyPairs.isArray()) {
                                    for (keyPair: JsonNode? in keyPairs) {
                                        try {
                                            val dkpw: DnsSecKeyPair? = DnsSecKeyPairImpl(keyPair, defaultTTL)
                                            if (!newKeyMap.containsKey(dkpw.getName())) {
                                                newKeyMap.put(dkpw.getName(), ArrayList())
                                            }
                                            val keyList: MutableList<DnsSecKeyPair?>? = newKeyMap.get(dkpw.getName())
                                            keyList.add(dkpw)
                                            newKeyMap.put(dkpw.getName(), keyList)
                                            LOGGER.debug("Added " + dkpw.toString() + " to incoming keyList")
                                        } catch (ex: JsonUtilsException) {
                                            LOGGER.fatal(
                                                "JsonUtilsException caught while parsing key for " + keyPair,
                                                ex
                                            )
                                        } catch (ex: TextParseException) {
                                            LOGGER.fatal(ex, ex)
                                        } catch (ex: IOException) {
                                            LOGGER.fatal(ex, ex)
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
                            LOGGER.debug("Found new keys in incoming keyMap; rebuilding zone caches")
                            trafficRouterManager.trackEvent("newDnsSecKeysFound")
                            keyMap = newKeyMap
                            getZoneManager().rebuildZoneCache()
                        } // no need to overwrite the keymap if they're the same, so no else leg
                    } else {
                        LOGGER.fatal("Unable to read keyPairData: " + keyPairData)
                    }
                } catch (ex: JsonUtilsException) {
                    LOGGER.fatal("JsonUtilsException caught while trying to maintain keyMap", ex)
                } catch (ex: RuntimeException) {
                    LOGGER.fatal("RuntimeException caught while trying to maintain keyMap", ex)
                }
            }
        }
    }

    private fun cleanRRSIGCache(
        oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?,
        newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?
    ) {
        synchronized(RRSIGCacheLock, {
            if (RRSIGCache.isEmpty() || (oldKeyMap == null) || getKeyDifferences(oldKeyMap, newKeyMap).isEmpty()) {
                return
            }
            val oldKeySize: Int = RRSIGCache.size
            val oldRRSIGSize: Int =
                RRSIGCache.values.stream().map(Function({ obj: ConcurrentMap<RRsetKey?, RRSIGRecord?>? -> obj.size }))
                    .reduce(0, BinaryOperator({ a: Int, b: Int -> Integer.sum(a, b) }))
            val now: Long = Date().getTime()
            val newRRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>? =
                ConcurrentHashMap()
            newKeyMap.forEach(BiConsumer({ name: String?, keyPairs: MutableList<DnsSecKeyPair?>? ->
                keyPairs.forEach(
                    Consumer({ keypair: DnsSecKeyPair? ->
                        val cacheKey: RRSIGCacheKey? =
                            RRSIGCacheKey(keypair.getPrivate().getEncoded(), keypair.getDNSKEYRecord().getAlgorithm())
                        val cacheValue: ConcurrentMap<RRsetKey?, RRSIGRecord?>? = RRSIGCache.get(cacheKey)
                        if (cacheValue != null) {
                            cacheValue.entries.removeIf(Predicate({ e: MutableMap.MutableEntry<RRsetKey?, RRSIGRecord?>? ->
                                e.value.getExpire().getTime() <= now
                            }))
                            newRRSIGCache.put(cacheKey, cacheValue)
                        }
                    })
                )
            }))
            RRSIGCache = newRRSIGCache
            val keySize: Int = RRSIGCache.size
            val RRSIGSize: Int =
                RRSIGCache.values.stream().map(Function({ obj: ConcurrentMap<RRsetKey?, RRSIGRecord?>? -> obj.size }))
                    .reduce(0, BinaryOperator({ a: Int, b: Int -> Integer.sum(a, b) }))
            LOGGER.info(
                ("DNSSEC keys were changed or removed so RRSIG cache was cleaned. Old key size: " + oldKeySize +
                        ", new key size: " + keySize + ", old RRSIG size: " + oldRRSIGSize + ", new RRSIG size: " + RRSIGSize)
            )
        })
    }

    // return the key names from newKeyMap that are different or missing from oldKeyMap
    private fun getKeyDifferences(
        newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?,
        oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?
    ): MutableSet<String?>? {
        val newKeyNames: MutableSet<String?>? = HashSet()
        for (newName: String? in newKeyMap.keys) {
            if (!oldKeyMap.containsKey(newName)) {
                newKeyNames.add(newName)
                continue
            }
            for (newKeyPair: DnsSecKeyPair? in newKeyMap.get(newName)) {
                var matched: Boolean = false
                for (keyPair: DnsSecKeyPair? in oldKeyMap.get(newName)) {
                    if ((newKeyPair == keyPair)) {
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

    private fun hasNewKeys(
        oldKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?,
        newKeyMap: MutableMap<String?, MutableList<DnsSecKeyPair?>?>?
    ): Boolean {
        val newOrChangedKeyNames: MutableSet<String?>? = getKeyDifferences(newKeyMap, oldKeyMap)
        if (!newOrChangedKeyNames.isEmpty()) {
            newOrChangedKeyNames.forEach(Consumer({ name: String? -> LOGGER.info("Found new or changed key for " + name) }))
            return true
        }
        return false
    }

    private fun fetchKeyPairData(cacheRegister: CacheRegister?): JsonNode? {
        if (!isDnssecEnabled()) {
            return null
        }
        var keyPairs: JsonNode? = null
        val mapper: ObjectMapper? = ObjectMapper()
        try {
            val keyUrl: String? = trafficOpsUtils.getUrl(
                "keystore.api.url",
                "https://\${toHostname}/api/2.0/cdns/name/\${cdnName}/dnsseckeys"
            )
            val config: JsonNode? = cacheRegister.getConfig()
            val timeout: Int = JsonUtils.optInt(config, "keystore.fetch.timeout", 30000) // socket timeouts are in ms
            val retries: Int = JsonUtils.optInt(config, "keystore.fetch.retries", 5)
            val wait: Int = JsonUtils.optInt(config, "keystore.fetch.wait", 5000) // 5 seconds
            if (fetcher == null) {
                fetcher =
                    ProtectedFetcher(trafficOpsUtils.getAuthUrl(), trafficOpsUtils.getAuthJSON().toString(), timeout)
            }
            for (i in 1..retries) {
                try {
                    val content: String? = fetcher.fetch(keyUrl)
                    if (content != null) {
                        keyPairs = mapper.readTree(content)
                        break
                    }
                } catch (ex: IOException) {
                    LOGGER.fatal(ex, ex)
                }
                try {
                    Thread.sleep(wait.toLong())
                } catch (ex: InterruptedException) {
                    LOGGER.fatal(ex, ex)
                    // break if we're interrupted
                    break
                }
            }
        } catch (ex: IOException) {
            LOGGER.fatal(ex, ex)
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
    private fun getKeyPairs(
        name: Name?,
        wantKsk: Boolean,
        wantSigningKey: Boolean,
        maxTTL: Long
    ): MutableList<DnsSecKeyPair?>? {
        val keyPairs: MutableList<DnsSecKeyPair?>? = keyMap.get(name.toString().toLowerCase())
        var signingKey: DnsSecKeyPair? = null
        if (keyPairs == null) {
            return null
        }
        val keys: MutableList<DnsSecKeyPair?>? = ArrayList()
        for (kpw: DnsSecKeyPair? in keyPairs) {
            val kn: Name? = kpw.getDNSKEYRecord().getName()
            val isKsk: Boolean = kpw.isKeySigningKey()
            if ((kn == name)) {
                if ((isKsk && !wantKsk) || (!isKsk && wantKsk)) {
                    LOGGER.debug("Skipping key: wantKsk = " + wantKsk + "; key: " + kpw.toString())
                    continue
                } else if (!wantSigningKey && (isExpiredKeyAllowed() || kpw.isKeyCached(maxTTL))) {
                    LOGGER.debug("key selected: " + kpw.toString())
                    keys.add(kpw)
                } else if (wantSigningKey) {
                    if (!kpw.isUsable()) { // effective date in the future
                        LOGGER.debug("Skipping unusable signing key: " + kpw.toString())
                        continue
                    } else if (!isExpiredKeyAllowed() && kpw.isExpired()) {
                        LOGGER.warn("Unable to use expired signing key: " + kpw.toString())
                        continue
                    }

                    // Locate the key with the earliest valid effective date accounting for expiration
                    if ((isKsk && wantKsk) || (!isKsk && !wantKsk)) {
                        if (signingKey == null) {
                            signingKey = kpw
                        } else if (signingKey.isExpired() && !kpw.isExpired()) {
                            signingKey = kpw
                        } else if (signingKey.isExpired() && kpw.isNewer(signingKey)) {
                            signingKey = kpw // if we have an expired key, try to find the most recent
                        } else if (!signingKey.isExpired() && !kpw.isExpired() && kpw.isOlder(signingKey)) {
                            signingKey = kpw // otherwise use the oldest valid/non-expired key
                        }
                    }
                }
            } else {
                LOGGER.warn("Invalid key for " + name + "; it is intended for " + kpw.toString())
            }
        }
        if (wantSigningKey && signingKey != null) {
            if (signingKey.isExpired()) {
                LOGGER.warn("Using expired signing key: " + signingKey.toString())
            } else {
                LOGGER.debug("Signing key selected: " + signingKey.toString())
            }
            keys.clear() // in case we have something in here for some reason (shouldn't happen)
            keys.add(signingKey)
        } else if (wantSigningKey && signingKey == null) {
            LOGGER.fatal("Unable to find signing key for " + name)
        }
        return keys
    }

    private fun calculateKeyExpiration(keyPairs: MutableList<DnsSecKeyPair?>?): Calendar? {
        val expiration: Calendar? = Calendar.getInstance()
        var earliest: Date? = null
        for (keyPair: DnsSecKeyPair? in keyPairs) {
            if (earliest == null) {
                earliest = keyPair.getExpiration()
            } else if (keyPair.getExpiration().before(earliest)) {
                earliest = keyPair.getExpiration()
            }
        }
        expiration.setTime(earliest)
        return expiration
    }

    private fun calculateSignatureExpiration(baseTimeInMillis: Long, records: MutableList<Record?>?): Calendar? {
        val expiration: Calendar? = Calendar.getInstance()
        val maxTTL: Long = ZoneUtils.getMaximumTTL(records) * 1000 // convert TTL to millis
        val signatureExpiration: Long = baseTimeInMillis + (maxTTL * getExpirationMultiplier())
        expiration.setTimeInMillis(signatureExpiration)
        return expiration
    }

    fun needsRefresh(type: ZoneCacheType?, zoneKey: ZoneKey?, refreshInterval: Int): Boolean {
        if (zoneKey is SignedZoneKey) {
            val szk: SignedZoneKey? = zoneKey as SignedZoneKey?
            val now: Long = System.currentTimeMillis()
            val nextRefresh: Long = now + (refreshInterval * 1000) // refreshInterval is in seconds, convert to millis
            if (nextRefresh >= szk.getRefreshHorizon()) {
                LOGGER.info(getRefreshMessage(type, szk, true, "refresh horizon approaching"))
                return true
            } else if (!isExpiredKeyAllowed() && now >= szk.getEarliestSigningKeyExpiration()) {
                /*
				 * The earliest signing key has expired, so force a resigning
				 * which will be done with new keys. This is because the keys themselves
				 * don't have expiry that's tied to DNSSEC; it's administrative, so
				 * we can be a little late on the swap.
				 */
                LOGGER.info(getRefreshMessage(type, szk, true, "signing key expiration"))
                return true
            } else {
                LOGGER.debug(getRefreshMessage(type, szk))
                return false
            }
        } else {
            LOGGER.debug(type.toString() + ": " + zoneKey.getName() + " is not a signed zone; no refresh needed")
            return false
        }
    }

    private fun getRefreshMessage(type: ZoneCacheType?, zoneKey: SignedZoneKey?): String? {
        return getRefreshMessage(type, zoneKey, false, null)
    }

    private fun getRefreshMessage(
        type: ZoneCacheType?,
        zoneKey: SignedZoneKey?,
        needsRefresh: Boolean,
        message: String?
    ): String? {
        val sb: StringBuilder? = StringBuilder()
        sb.append(type)
        sb.append(": timestamp for ")
        sb.append(zoneKey.getName())
        sb.append(" is ")
        sb.append(zoneKey.getTimestampDate())
        sb.append("; expires ")
        sb.append(zoneKey.getMinimumSignatureExpiration().getTime())
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
        val maxTTL: Long = ZoneUtils.getMaximumTTL(records)
        val kskPairs: MutableList<DnsSecKeyPair?>? = getZoneSigningKSKPair(name, maxTTL)
        val zskPairs: MutableList<DnsSecKeyPair?>? = getZoneSigningZSKPair(name, maxTTL)

        // TODO: do we really need to fully sign the apex keyset? should the digest be config driven?
        if (kskPairs != null && zskPairs != null) {
            if (!kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                val signatureExpiration: Calendar? = calculateSignatureExpiration(zoneKey.getTimestamp(), records)
                val kskExpiration: Calendar? = calculateKeyExpiration(kskPairs)
                val zskExpiration: Calendar? = calculateKeyExpiration(zskPairs)
                val now: Long = System.currentTimeMillis()
                val start: Calendar? = Calendar.getInstance()
                start.setTimeInMillis(now)
                start.add(Calendar.HOUR, -1)
                LOGGER.info("Signing zone " + name + " with start " + start.getTime() + " and expiration " + signatureExpiration.getTime())
                val signedRecords: MutableList<Record?>?
                val zoneSigner: ZoneSigner? = ZoneSignerImpl()
                signedRecords = zoneSigner.signZone(
                    records, kskPairs, zskPairs, start.getTime(),
                    signatureExpiration.getTime(), if (isRRSIGCacheEnabled()) RRSIGCache else null
                )
                zoneKey.setMinimumSignatureExpiration(signedRecords, signatureExpiration)
                zoneKey.setKSKExpiration(kskExpiration)
                zoneKey.setZSKExpiration(zskExpiration)
                return signedRecords
            } else {
                LOGGER.warn("Unable to sign zone " + name + "; have " + kskPairs.size + " KSKs and " + zskPairs.size + " ZSKs")
            }
        } else {
            LOGGER.warn("Unable to sign zone " + name + "; ksks or zsks are null")
        }
        return records
    }

    @Throws(NoSuchAlgorithmException::class, IOException::class)
    fun generateDSRecords(name: Name?, maxTTL: Long): MutableList<Record?>? {
        val records: MutableList<Record?>? = ArrayList()
        if (isDnssecEnabled() && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            val config: JsonNode? = getCacheRegister().getConfig()
            val kskPairs: MutableList<DnsSecKeyPair?>? = getKSKPairs(name, maxTTL)
            val zskPairs: MutableList<DnsSecKeyPair?>? = getZSKPairs(name, maxTTL)
            if ((kskPairs != null) && (zskPairs != null) && !kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                // these records go into the CDN TLD, so don't use the DS' TTLs; use the CDN's.
                val dsTtl: Long? = ZoneUtils.getLong(config.get("ttls"), "DS", 60)
                for (kp: DnsSecKeyPair? in kskPairs) {
                    val zoneSigner: ZoneSigner? = ZoneSignerImpl()
                    val dsRecord: DSRecord? =
                        zoneSigner.calculateDSRecord(kp.getDNSKEYRecord(), DSRecord.SHA256_DIGEST_ID, dsTtl)
                    LOGGER.debug(name.toString() + ": adding DS record " + dsRecord)
                    records.add(dsRecord)
                }
            }
        }
        return records
    }

    @Throws(NoSuchAlgorithmException::class, IOException::class)
    fun generateDNSKEYRecords(name: Name?, maxTTL: Long): MutableList<Record?>? {
        val list: MutableList<Record?>? = ArrayList()
        if (isDnssecEnabled() && name.subdomain(ZoneManager.Companion.getTopLevelDomain())) {
            val kskPairs: MutableList<DnsSecKeyPair?>? = getKSKPairs(name, maxTTL)
            val zskPairs: MutableList<DnsSecKeyPair?>? = getZSKPairs(name, maxTTL)
            if ((kskPairs != null) && (zskPairs != null) && !kskPairs.isEmpty() && !zskPairs.isEmpty()) {
                for (kp: DnsSecKeyPair? in kskPairs) {
                    LOGGER.debug(name.toString() + ": DNSKEY record " + kp.getDNSKEYRecord())
                    list.add(kp.getDNSKEYRecord())
                }
                for (kp: DnsSecKeyPair? in zskPairs) {
                    // TODO: make adding zsk to parent zone configurable?
                    LOGGER.debug(name.toString() + ": DNSKEY record " + kp.getDNSKEYRecord())
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

    private fun generateZoneKey(
        name: Name?,
        list: MutableList<Record?>?,
        dynamicRequest: Boolean,
        dnssecRequest: Boolean
    ): ZoneKey? {
        if (dynamicRequest && !dnssecRequest) {
            return ZoneKey(name, list)
        } else if ((isDnssecEnabled(name) && name.subdomain(ZoneManager.Companion.getTopLevelDomain()))) {
            return SignedZoneKey(name, list)
        } else {
            return ZoneKey(name, list)
        }
    }

    fun isDnssecEnabled(): Boolean {
        return dnssecEnabled
    }

    private fun isDnssecEnabled(name: Name?): Boolean {
        return dnssecEnabled && keyMap.containsKey(name.toString().toLowerCase())
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
        private val LOGGER: Logger? = Logger.getLogger(SignatureManager::class.java)
        private var RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>? =
            ConcurrentHashMap()
        private val RRSIGCacheLock: Any? = Any() // to ensure that the RRSIGCache is totally empty if disabled
        private var keyMaintenanceExecutor: ScheduledExecutorService? = null
    }

    init {
        setCacheRegister(cacheRegister)
        setTrafficOpsUtils(trafficOpsUtils)
        setZoneManager(zoneManager)
        setRRSIGCacheEnabled(cacheRegister.getConfig())
        initKeyMap()
    }
}