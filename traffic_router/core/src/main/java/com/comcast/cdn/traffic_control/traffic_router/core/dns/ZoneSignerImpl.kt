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
import org.apache.log4j.Logger
import org.xbill.DNS.Name
import org.xbill.DNS.Record
import org.xbill.DNS.Type
import java.lang.Exception
import java.util.*
import java.util.function.Consumer
import java.util.function.Function
import java.util.function.Predicate
import java.util.stream.Stream

class ZoneSignerImpl constructor() : ZoneSigner {
    private fun toRRStream(rrSet: RRset?): Stream<Record?>? {
        val iterable: Iterable<Record?>? = Iterable<Record?>({ rrSet.rrs(false) })
        return StreamSupport.stream(iterable.spliterator(), false)
    }

    private fun toRRSigStream(rrSset: RRset?): Stream<Record?>? {
        val iterable: Iterable<Record?>? = Iterable<Record?>({ rrSset.sigs() })
        return StreamSupport.stream(iterable.spliterator(), false)
    }

    private fun sign(
        rrset: RRset?,
        dnskeyRecord: DNSKEYRecord?,
        privateKey: PrivateKey?,
        inception: Date?,
        expiration: Date?
    ): RRSIGRecord? {
        try {
            return DNSSEC.sign(rrset, dnskeyRecord, privateKey, inception, expiration)
        } catch (e: DNSSECException) {
            val message: String? = String.format(
                "Failed to sign Resource Record Set for %s %d %d %d : %s",
                dnskeyRecord.getName(),
                dnskeyRecord.getDClass(),
                dnskeyRecord.getType(),
                dnskeyRecord.getTTL(),
                e.message
            )
            LOGGER.error(message, e)
            return null
        }
    }

    private fun isSignatureAlmostExpired(inception: Date?, expiration: Date?, now: Date?): Boolean {
        // now is over halfway through validity period
        return now.getTime() > inception.getTime() + ((expiration.getTime() - inception.getTime()) / 2)
    }

    private fun signRRset(
        rrSet: RRset?, kskPairs: MutableList<DnsSecKeyPair?>?, zskPairs: MutableList<DnsSecKeyPair?>?,
        inception: Date?, expiration: Date?,
        RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>?
    ): RRset? {
        val signatures: MutableList<RRSIGRecord?>? = ArrayList()
        val pairs: MutableList<DnsSecKeyPair?>? = if (rrSet.getType() == Type.DNSKEY) kskPairs else zskPairs
        val now: Date? = Date()
        pairs.forEach(Consumer({ pair: DnsSecKeyPair? ->
            val dnskeyRecord: DNSKEYRecord? = pair.getDNSKEYRecord()
            val privateKey: PrivateKey? = pair.getPrivate()
            var signature: RRSIGRecord? = null
            try {
                if (RRSIGCache == null) {
                    signature = sign(rrSet, dnskeyRecord, privateKey, inception, expiration)
                } else {
                    val sigMap: ConcurrentMap<RRsetKey?, RRSIGRecord?>? = RRSIGCache.computeIfAbsent(
                        RRSIGCacheKey(privateKey.getEncoded(), dnskeyRecord.getAlgorithm()),
                        Function<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>({ rrsigCacheKey: RRSIGCacheKey? -> ConcurrentHashMap() })
                    )
                    signature = sigMap.computeIfAbsent(
                        RRsetKey(rrSet),
                        Function({ k: RRsetKey? -> sign(rrSet, dnskeyRecord, privateKey, inception, expiration) })
                    )
                    if (signature != null && isSignatureAlmostExpired(
                            signature.getTimeSigned(),
                            signature.getExpire(),
                            now
                        )
                    ) {
                        signature = sigMap.compute(
                            RRsetKey(rrSet),
                            BiFunction({ k: RRsetKey?, v: RRSIGRecord? ->
                                sign(
                                    rrSet,
                                    dnskeyRecord,
                                    privateKey,
                                    inception,
                                    expiration
                                )
                            })
                        )
                    }
                }
            } catch (e: Exception) {
                val message: String? = String.format(
                    "Failed to sign Resource Record Set for %s %d %d %d : %s",
                    dnskeyRecord.getName(),
                    dnskeyRecord.getDClass(),
                    dnskeyRecord.getType(),
                    dnskeyRecord.getTTL(),
                    e.message
                )
                LOGGER.error(message, e)
            }
            if (signature != null) {
                signatures.add(signature)
            }
        }))
        val signedRRset: RRset? = RRset()
        toRRStream(rrSet).forEach(Consumer({ r: Record? -> signedRRset.addRR(r) }))
        signatures.forEach(Consumer({ r: RRSIGRecord? -> signedRRset.addRR(r) }))
        return signedRRset
    }

    private fun findSoaRecord(records: MutableList<Record?>?): SOARecord? {
        val soaRecordOptional: Optional<Record?>? =
            records.stream().filter(Predicate({ record: Record? -> record is SOARecord })).findFirst()
        if (soaRecordOptional.isPresent()) {
            return soaRecordOptional.get() as SOARecord?
        }
        return null
    }

    private fun createNsecRecords(records: MutableList<Record?>?): MutableList<NSECRecord?>? {
        val recordMap: MutableMap<Name?, MutableList<Record?>?>? = records.stream().collect(
            Collectors.groupingBy(
                Function({ obj: Record? -> obj.getName() })
            )
        )
        val names: MutableList<Name?>? = recordMap.keys.stream().sorted().collect(Collectors.toList())
        val nextNameTuples: MutableMap<Name?, Name?>? = HashMap()
        for (i in names.indices) {
            val k: Name? = names.get(i)
            val v: Name? = names.get((i + 1) % names.size)
            nextNameTuples.put(k, v)
        }
        val soaRecord: SOARecord? = findSoaRecord(records)
        if (soaRecord == null) {
            LOGGER.warn("No SOA record found, this extremely likely to produce DNSSEC errors")
        }
        val minimumSoaTtl: Long = if (soaRecord != null) soaRecord.getMinimum() else 0L
        val nsecRecords: MutableList<NSECRecord?>? = ArrayList()
        names.forEach(Consumer({ name: Name? ->
            val mostTypes: IntArray? =
                recordMap.get(name).stream().mapToInt(ToIntFunction({ obj: Record? -> obj.getType() })).toArray()
            val allTypes: IntArray? = IntArray(mostTypes.size + 2)
            System.arraycopy(mostTypes, 0, allTypes, 0, mostTypes.size)
            allTypes.get(mostTypes.size) = Type.NSEC
            allTypes.get(mostTypes.size + 1) = Type.RRSIG
            nsecRecords.add(NSECRecord(name, DClass.IN, minimumSoaTtl, nextNameTuples.get(name), allTypes))
        }))
        return nsecRecords
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    public override fun signZone(
        records: MutableList<Record?>?, kskPairs: MutableList<DnsSecKeyPair?>?,
        zskPairs: MutableList<DnsSecKeyPair?>?, inception: Date?, expiration: Date?,
        RRSIGCache: ConcurrentMap<RRSIGCacheKey?, ConcurrentMap<RRsetKey?, RRSIGRecord?>?>?
    ): MutableList<Record?>? {
        val nsecRecords: MutableList<NSECRecord?>? = createNsecRecords(records)
        records.addAll(nsecRecords)
        Collections.sort(records, Comparator({ record1: Record?, record2: Record? ->
            if (record1.getType() != Type.SOA && record2.getType() != Type.SOA) {
                return@sort record1.compareTo(record2)
            }
            var x: Int = record1.getName().compareTo(record2.getName())
            if (x != 0) {
                return@sort x
            }
            x = record1.getDClass() - record2.getDClass()
            if (x != 0) {
                return@sort x
            }
            if (record1.getType() != record2.getType()) {
                return@sort if (record1.getType() == Type.SOA) -1 else 1
            }
            record1.compareTo(record2)
        }))
        val rrSets: MutableList<RRset?>? = RRSetsBuilder().build(records)
        val signedRrSets: MutableList<RRset?>? = rrSets.stream()
            .map(Function({ rRset: RRset? -> signRRset(rRset, kskPairs, zskPairs, inception, expiration, RRSIGCache) }))
            .sorted(Comparator({ rRset1: RRset?, rRset2: RRset? -> rRset1.getName().compareTo(rRset2.getName()) }))
            .collect(Collectors.toList())
        val signedZoneRecords: MutableList<Record?>? = ArrayList()
        signedRrSets.forEach(Consumer({ rrSet: RRset? ->
            signedZoneRecords.addAll(toRRStream(rrSet).collect(Collectors.toList()))
            signedZoneRecords.addAll(toRRSigStream(rrSet).collect(Collectors.toList()))
        }))
        return signedZoneRecords
    }

    public override fun calculateDSRecord(dnskeyRecord: DNSKEYRecord?, digestId: Int, ttl: Long): DSRecord? {
        LOGGER.info("Calculating DS Records for " + dnskeyRecord.getName())
        return DSRecord(dnskeyRecord.getName(), DClass.IN, ttl, digestId, dnskeyRecord)
    }

    companion object {
        private val LOGGER: Logger? = Logger.getLogger(ZoneSignerImpl::class.java)
    }
}