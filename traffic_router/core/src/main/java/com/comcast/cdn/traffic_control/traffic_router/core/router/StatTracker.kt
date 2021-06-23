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
package com.comcast.cdn.traffic_control.traffic_router.core.router

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
import java.util.Enumeration
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
import org.xbill.DNS.Name
import org.xbill.DNS.Zone

class StatTracker constructor() {
    class Tallies constructor() {
        fun getCzCount(): Int {
            return czCount
        }

        fun setCzCount(czCount: Int) {
            this.czCount = czCount
        }

        fun getGeoCount(): Int {
            return geoCount
        }

        fun setGeoCount(geoCount: Int) {
            this.geoCount = geoCount
        }

        fun getDeepCzCount(): Int {
            return deepCzCount
        }

        fun setDeepCzCount(deepCzCount: Int) {
            this.deepCzCount = deepCzCount
        }

        fun getDsrCount(): Int {
            return dsrCount
        }

        fun getMissCount(): Int {
            return missCount
        }

        fun setMissCount(missCount: Int) {
            this.missCount = missCount
        }

        fun getErrCount(): Int {
            return errCount
        }

        fun setErrCount(errCount: Int) {
            this.errCount = errCount
        }

        fun getStaticRouteCount(): Int {
            return staticRouteCount
        }

        fun setStaticRouteCount(staticRouteCount: Int) {
            this.staticRouteCount = staticRouteCount
        }

        fun getFedCount(): Int {
            return fedCount
        }

        fun setFedCount(fedCount: Int) {
            this.fedCount = fedCount
        }

        fun getRegionalDeniedCount(): Int {
            return regionalDeniedCount
        }

        fun setRegionalDeniedCount(regionalDeniedCount: Int) {
            this.regionalDeniedCount = regionalDeniedCount
        }

        fun getRegionalAlternateCount(): Int {
            return regionalAlternateCount
        }

        fun setRegionalAlternateCount(regionalAlternateCount: Int) {
            this.regionalAlternateCount = regionalAlternateCount
        }

        var czCount: Int = 0
        var geoCount: Int = 0
        var deepCzCount: Int = 0
        var missCount: Int = 0
        var dsrCount: Int = 0
        var errCount: Int = 0
        var staticRouteCount: Int = 0
        var fedCount: Int = 0
        var regionalDeniedCount: Int = 0
        var regionalAlternateCount: Int = 0
    }

    class Track constructor() {
        /**
         * RouteType represents the type of routing performed/to be performed by Traffic Router.
         */
        enum class RouteType {
            /**
             * This value indicates DNS routing is taking/has taken/will take place.
             */
            DNS,

            /**
             * This value indicates HTTP routing is taking/has taken/will take place.
             */
            HTTP
        }

        /**
         * ResultType represents the final result of attempting to route a request.
         */
        enum class ResultType {
            /**
             * This value indicates that an error occurred and routing could not be successfully completed.
             */
            ERROR,

            /**
             * This value indicates that routing was satisfied by a mapping in Coverage Zone configuration.
             */
            CZ,

            /**
             * This value indicates that routing was satisfied by geo-locating the client.
             */
            GEO,

            /**
             * This value indicates that geo-location of the client failed, and they were directed to an appropriate "miss" location.
             */
            MISS,

            /**
             * This value indicates that routing was satisfied by a static DNS entry configured on a Delivery Service.
             */
            STATIC_ROUTE,

            /**
             *
             */
            DS_REDIRECT,

            /**
             * This value indicates that routing could not be performed, because no Delivery Service could be found to match
             * the client request.
             */
            DS_MISS,

            /**
             *
             */
            INIT,

            /**
             * This value indicates that the client was routed according to Federation mappings.
             */
            FED,

            /**
             *
             */
            RGDENY,

            /**
             *
             */
            RGALT,

            /**
             *
             */
            GEO_REDIRECT,

            /**
             * This value indicates that routing was satisfied by a mapping in Deep Coverage Zone configuration.
             */
            DEEP_CZ,

            /**
             * This value indicates that routing was blocked in accordance with anonymous blocking configurations.
             */
            ANON_BLOCK,

            /**
             * This value indicates that routing was based on the default lat/long of the delivery service, because maxmind
             * returned the centre of the country as the client location, due to the CZF not being able to resolve the client IP
             * to a valid location.
             */
            GEO_DS
        }

        enum class ResultDetails {
            NO_DETAILS, DS_NOT_FOUND, DS_TLS_MISMATCH, DS_NO_BYPASS, DS_BYPASS, DS_CZ_ONLY, DS_CLIENT_GEO_UNSUPPORTED, GEO_NO_CACHE_FOUND, REGIONAL_GEO_NO_RULE, REGIONAL_GEO_ALTERNATE_WITHOUT_CACHE, REGIONAL_GEO_ALTERNATE_WITH_CACHE, DS_CZ_BACKUP_CG, DS_INVALID_ROUTING_NAME, LOCALIZED_DNS
        }

        enum class ResultCode {
            NO_RESULT_CODE, NXDOMAIN, NODATA
        }

        var time: Long = 0
        var routeType: RouteType? = null
        var fqdn: String? = null
        var resultCode: ResultCode? = ResultCode.NO_RESULT_CODE
        var result: ResultType? = ResultType.ERROR
        var resultDetails: ResultDetails? = null
        var resultLocation: Geolocation? = null
        var clientGeolocation // the GEO info always retrieved from GEO DB, not from Cache Location
                : Geolocation? = null
        var isClientGeolocationQueried: Boolean = false
        var regionalGeoResult: RegionalGeoResult? = null
        var fromBackupCzGroup: Boolean = false

        // in memory switch to track if need to continue geo based
        // defaulting to true, changes the false by router at runtime when primary cache group is configured using fallbackToClosedGeoLoc
        // to false and backup group list is configured and failing
        var continueGeo: Boolean = true
        public override fun toString(): String {
            return fqdn + " - " + result
        }

        fun setRouteType(routeType: RouteType?, fqdn: String?) {
            this.routeType = routeType
            this.fqdn = fqdn
        }

        fun setResultCode(zone: Zone?, qname: Name?, qtype: Int) {
            if (zone == null) {
                return
            }
            val sr: SetResponse? = zone.findRecords(qname, qtype)
            if (sr.isNXDOMAIN()) {
                resultCode = ResultCode.NXDOMAIN
            } else if (sr.isNXRRSET()) {
                resultCode = ResultCode.NODATA
            }
        }

        fun getResultCode(): ResultCode? {
            return resultCode
        }

        fun setResult(result: ResultType?) {
            this.result = result
        }

        fun getResult(): ResultType? {
            return result
        }

        fun setResultDetails(resultDetails: ResultDetails?) {
            this.resultDetails = resultDetails
        }

        fun getResultDetails(): ResultDetails? {
            return resultDetails
        }

        fun setResultLocation(resultLocation: Geolocation?) {
            this.resultLocation = resultLocation
        }

        fun getResultLocation(): Geolocation? {
            return resultLocation
        }

        fun setClientGeolocation(clientGeolocation: Geolocation?) {
            this.clientGeolocation = clientGeolocation
        }

        fun getClientGeolocation(): Geolocation? {
            return clientGeolocation
        }

        fun setClientGeolocationQueried(isClientGeolocationQueried: Boolean) {
            this.isClientGeolocationQueried = isClientGeolocationQueried
        }

        fun isClientGeolocationQueried(): Boolean {
            return isClientGeolocationQueried
        }

        fun setRegionalGeoResult(regionalGeoResult: RegionalGeoResult?) {
            this.regionalGeoResult = regionalGeoResult
        }

        fun getRegionalGeoResult(): RegionalGeoResult? {
            return regionalGeoResult
        }

        fun setFromBackupCzGroup(fromBackupCzGroup: Boolean) {
            this.fromBackupCzGroup = fromBackupCzGroup
        }

        fun isFromBackupCzGroup(): Boolean {
            return fromBackupCzGroup
        }

        fun start() {
            time = System.currentTimeMillis()
        }

        fun end() {
            time = System.currentTimeMillis() - time
        }

        init {
            start()
        }
    }

    private val dnsMap: MutableMap<String?, Tallies?>? = HashMap()
    private val httpMap: MutableMap<String?, Tallies?>? = HashMap()
    fun getDnsMap(): MutableMap<String?, Tallies?>? {
        return dnsMap
    }

    fun getHttpMap(): MutableMap<String?, Tallies?>? {
        return httpMap
    }

    fun getTotalDnsCount(): Long {
        return totalDnsCount
    }

    fun getAverageDnsTime(): Long {
        if (totalDnsCount == 0L) {
            return 0
        }
        return totalDnsTime / totalDnsCount
    }

    fun getTotalHttpCount(): Long {
        return totalHttpCount
    }

    fun getAverageHttpTime(): Long {
        if (totalHttpCount == 0L) {
            return 0
        }
        return totalHttpTime / totalHttpCount
    }

    fun getTotalDsMissCount(): Long {
        return totalDsMissCount
    }

    fun setTotalDsMissCount(totalDsMissCount: Long) {
        this.totalDsMissCount = totalDsMissCount
    }

    private var totalDnsCount: Long = 0
    private var totalDnsTime: Long = 0
    private var totalHttpCount: Long = 0
    private var totalHttpTime: Long = 0
    private var totalDsMissCount: Long = 0
    fun getUpdateTracker(): MutableMap<String?, Long?>? {
        return TrafficRouterManager.Companion.getTimeTracker()
    }

    fun getAppStartTime(): Long {
        return appStartTime
    }

    private var appStartTime: Long = 0
    fun saveTrack(t: Track?) {
        if (t.result == ResultType.DS_MISS) {
            // don't tabulate this, it's for a DS that doesn't exist
            totalDsMissCount++
            return
        }
        t.end()
        synchronized(this, {
            val map: MutableMap<String?, Tallies?>?
            val fqdn: String? = if (t.fqdn == null) "null" else t.fqdn
            if (t.routeType == RouteType.DNS) {
                totalDnsCount++
                totalDnsTime += t.time
                map = dnsMap
                if (t.resultDetails == ResultDetails.LOCALIZED_DNS) {
                    return
                }
            } else {
                totalHttpCount++
                totalHttpTime += t.time
                map = httpMap
            }
            map.putIfAbsent(fqdn, Tallies())
            incTally(t, map.get(fqdn))
        })
    }

    fun init() {
        appStartTime = System.currentTimeMillis()
    }

    fun initialize(initMap: MutableMap<String?, MutableList<String?>?>?, cacheRegister: CacheRegister?) {
        for (dsId: String? in initMap.keys) {
            val dsNames: MutableList<String?>? = initMap.get(dsId)
            val ds: DeliveryService? = cacheRegister.getDeliveryService(dsId)
            if (ds != null) {
                for (i in dsNames.indices) {
                    val t: Track? = getTrack()
                    val dsName: StringBuffer? = StringBuffer(dsNames.get(i))
                    var rt: RouteType?
                    if (ds.isDns()) {
                        rt = RouteType.DNS
                        if (i == 0) {
                            dsName.insert(0, ds.getRoutingName() + ".")
                        } else {
                            continue
                        }
                    } else {
                        rt = RouteType.HTTP
                        dsName.insert(0, ds.getRoutingName() + ".")
                    }
                    t.setRouteType(rt, dsName.toString())
                    t.setResult(ResultType.INIT)
                    t.end()
                    saveTrack(t)
                }
            }
        }
    }

    companion object {
        fun getTrack(): Track? {
            return Track()
        }

        private fun incTally(t: Track?, tallies: Tallies?) {
            when (t.result) {
                ResultType.ERROR -> tallies.errCount++
                ResultType.CZ -> tallies.czCount++
                ResultType.GEO -> tallies.geoCount++
                ResultType.DEEP_CZ -> tallies.deepCzCount++
                ResultType.MISS -> tallies.missCount++
                ResultType.DS_REDIRECT -> tallies.dsrCount++
                ResultType.STATIC_ROUTE -> tallies.staticRouteCount++
                ResultType.FED -> tallies.fedCount++
                ResultType.RGDENY -> tallies.regionalDeniedCount++
                ResultType.RGALT -> tallies.regionalAlternateCount++
                else -> {
                }
            }
        }
    }
}