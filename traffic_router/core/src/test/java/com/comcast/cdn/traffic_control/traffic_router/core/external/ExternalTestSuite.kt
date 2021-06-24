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

import kotlin.Throws
import java.lang.Exception
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringTarget
import org.powermock.core.classloader.annotations.PrepareForTest
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import org.junit.runner.RunWith
import org.powermock.modules.junit4.PowerMockRunner
import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryServiceMatcher
import com.comcast.cdn.traffic_control.traffic_router.core.request.HTTPRequest
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringResult
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringGeolocationComparator
import org.junit.Before
import com.comcast.cdn.traffic_control.traffic_router.shared.ZoneTestRecords
import org.xbill.DNS.RRset
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRSetsBuilder
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP
import java.net.InetAddress
import java.io.ByteArrayInputStream
import java.net.ServerSocket
import java.util.concurrent.BlockingQueue
import java.lang.Runnable
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.TCP.TCPSocketHandler
import org.xbill.DNS.DClass
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessRecord
import org.xbill.DNS.Rcode
import java.lang.RuntimeException
import org.powermock.api.mockito.PowerMockito
import java.net.DatagramSocket
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP
import org.xbill.DNS.OPTRecord
import java.util.concurrent.atomic.AtomicInteger
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.UDP.UDPPacketHandler
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest.FakeAbstractProtocol
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSAccessEventBuilder
import java.lang.System
import com.comcast.cdn.traffic_control.traffic_router.core.dns.protocol.AbstractProtocolTest
import java.net.Inet4Address
import org.xbill.DNS.ARecord
import org.xbill.DNS.WireParseException
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouter
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheRegister
import org.xbill.DNS.NSRecord
import org.xbill.DNS.SOARecord
import org.xbill.DNS.ClientSubnetOption
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import org.xbill.DNS.EDNSOption
import java.util.HashSet
import com.comcast.cdn.traffic_control.traffic_router.core.util.IntegrationTest
import java.util.HashMap
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManagerTest
import com.google.common.net.InetAddresses
import org.xbill.DNS.TextParseException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneManager
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node.IPVersions
import com.google.common.cache.CacheStats
import org.junit.BeforeClass
import java.nio.file.Paths
import com.comcast.cdn.traffic_control.traffic_router.core.TestBase
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DNSException
import com.comcast.cdn.traffic_control.traffic_router.core.dns.NameServerMain
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImpl
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPair
import com.comcast.cdn.traffic_control.traffic_router.core.dns.DnsSecKeyPairImpl
import org.xbill.DNS.DNSKEYRecord
import java.security.PrivateKey
import org.xbill.DNS.RRSIGRecord
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImplTest.IsRRsetTypeA
import com.comcast.cdn.traffic_control.traffic_router.core.dns.ZoneSignerImplTest.IsRRsetTypeNSEC
import java.util.concurrent.ConcurrentMap
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRSIGCacheKey
import com.comcast.cdn.traffic_control.traffic_router.core.dns.RRsetKey
import java.util.concurrent.ConcurrentHashMap
import com.comcast.cdn.traffic_control.traffic_router.core.dns.SignatureManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.TrafficOpsUtils
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker
import org.xbill.DNS.SetResponse
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultType
import org.xbill.DNS.NSECRecord
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatTracker.Track.ResultDetails
import com.comcast.cdn.traffic_control.traffic_router.core.loc.GeolocationDatabaseUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.MaxmindGeolocationService
import com.comcast.cdn.traffic_control.traffic_router.core.loc.GeoTest
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIp
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseService
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpWhitelist
import java.io.IOException
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeTest
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeo
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoResult.RegionalGeoResultType
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import java.net.MalformedURLException
import com.comcast.cdn.traffic_control.traffic_router.core.router.HTTPRouteResult
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.edge.CacheLocation.LocalizationMethod
import com.comcast.cdn.traffic_control.traffic_router.core.loc.MaxmindGeoIP2Test
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule.PostalsType
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoRule
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode.SuperNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.RegionalGeoCoordinateRange
import com.comcast.cdn.traffic_control.traffic_router.core.loc.Federation
import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableTreeSet
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationMapping
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AbstractServiceUpdater
import java.nio.file.Path
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AbstractServiceUpdaterTest.Updater
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationMappingBuilder
import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.model.CityResponse
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseServiceTest
import com.maxmind.geoip2.model.AnonymousIpResponse
import com.maxmind.geoip2.exception.GeoIp2Exception
import java.util.TreeSet
import com.comcast.cdn.traffic_control.traffic_router.core.http.HTTPAccessEventBuilder
import com.comcast.cdn.traffic_control.traffic_router.core.http.HTTPAccessRecord
import java.lang.StringBuffer
import com.comcast.cdn.traffic_control.traffic_router.core.util.Fetcher
import java.io.InputStreamReader
import org.powermock.core.classloader.annotations.PowerMockIgnore
import java.io.BufferedReader
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringWatcher
import java.lang.InterruptedException
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcherTest
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableStringByLength
import com.comcast.cdn.traffic_control.traffic_router.core.config.ConfigHandler
import java.lang.Void
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import com.comcast.cdn.traffic_control.traffic_router.core.config.CertificateChecker
import com.comcast.cdn.traffic_control.traffic_router.core.hash.ConsistentHasher
import com.comcast.cdn.traffic_control.traffic_router.core.ds.Dispersion
import com.comcast.cdn.traffic_control.traffic_router.core.router.DNSRouteResult
import com.comcast.cdn.traffic_control.traffic_router.core.request.DNSRequest
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.router.StatelessTrafficRouterTest
import com.comcast.cdn.traffic_control.traffic_router.core.router.LocationComparator
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.comcast.cdn.traffic_control.traffic_router.secure.Pkcs1
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesClient
import com.comcast.cdn.traffic_control.traffic_router.core.hash.NumberSearcher
import com.comcast.cdn.traffic_control.traffic_router.core.hash.DefaultHashable
import com.comcast.cdn.traffic_control.traffic_router.core.hash.MD5HashFunction
import com.comcast.cdn.traffic_control.traffic_router.core.hash.Hashable
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
import javax.net.ssl.SSLSession
import org.hamcrest.number.IsCloseTo
import com.comcast.cdn.traffic_control.traffic_router.core.http.RouterFilter
import java.net.InetSocketAddress
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
import javax.management.ObjectName
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificatesMBean
import com.comcast.cdn.traffic_control.traffic_router.shared.DeliveryServiceCertificates
import org.springframework.context.support.FileSystemXmlApplicationContext
import kotlin.jvm.JvmStatic
import org.apache.catalina.startup.Catalina
import org.apache.catalina.core.StandardService
import java.util.stream.Collectors
import org.apache.catalina.core.StandardHost
import org.apache.catalina.core.StandardContext
import org.apache.log4j.Level
import org.apache.log4j.LogManager
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.experimental.categories.Category
import org.springframework.util.SocketUtils
import java.io.File
import java.nio.file.Files

@Category(ExternalTest::class)
@RunWith(Suite::class)
@SuiteClasses(
    SteeringTest::class,
    ConsistentHashTest::class,
    CoverageZoneTest::class,
    DeliveryServicesTest::class,
    LocationsTest::class,
    RouterTest::class,
    StatsTest::class,
    ZonesTest::class
)
object ExternalTestSuite {
    const val TRAFFIC_MONITOR_BOOTSTRAP_LOCAL = "TRAFFIC_MONITOR_BOOTSTRAP_LOCAL"
    const val TRAFFIC_MONITOR_HOSTS = "TRAFFIC_MONITOR_HOSTS"
    var FAKE_SERVER: String? = null
    private var catalinaTrafficRouter: CatalinaTrafficRouter? = null
    private var httpDataServer: HttpDataServer? = null
    private var tmpDeployDir: File? = null
    private var testHttpServerPort = 0
    @Throws(Exception::class)
    fun addToEnv(envVars: Map<String, String?>?) {
        val envMap = System.getenv()
        val clazz: Class<*> = envMap.javaClass
        val m = clazz.getDeclaredField("m")
        m.isAccessible = true
        val mutableEnvMap = m[envMap] as MutableMap<String, String?>
        mutableEnvMap.putAll(envVars!!)
    }

    @Throws(Exception::class)
    fun setupFakeServers() {
        // Set up a local server that can hand out
        // cr-config and cr-states (i.e. fake traffic monitor endpoints)
        // czmap
        // federations
        // steering
        // fake setting a cookie
        FAKE_SERVER = "localhost:" + testHttpServerPort + ";"
        val additionalEnvironment: MutableMap<String, String?> = HashMap()
        additionalEnvironment[TRAFFIC_MONITOR_BOOTSTRAP_LOCAL] = "true"
        additionalEnvironment[TRAFFIC_MONITOR_HOSTS] = FAKE_SERVER
        if (System.getenv(TRAFFIC_MONITOR_HOSTS) != null) {
            println("External Test Suite overriding env var [" + TRAFFIC_MONITOR_HOSTS + "] to " + FAKE_SERVER)
        }
        if (System.getenv(TRAFFIC_MONITOR_BOOTSTRAP_LOCAL) != null) {
            println("External Test Suite overriding env var [" + TRAFFIC_MONITOR_BOOTSTRAP_LOCAL + "] to true")
        }
        addToEnv(additionalEnvironment)
        MatcherAssert.assertThat(System.getenv(TRAFFIC_MONITOR_BOOTSTRAP_LOCAL), Matchers.equalTo("true"))
        MatcherAssert.assertThat(System.getenv(TRAFFIC_MONITOR_HOSTS), Matchers.equalTo(FAKE_SERVER))
        httpDataServer = HttpDataServer(testHttpServerPort)
        httpDataServer!!.start(testHttpServerPort)
    }

    @BeforeClass
    @Throws(Exception::class)
    fun beforeClass() {
        testHttpServerPort = SocketUtils.findAvailableTcpPort()
        System.setProperty("testHttpServerPort", "" + testHttpServerPort)
        System.setProperty("routerHttpPort", "" + SocketUtils.findAvailableTcpPort())
        System.setProperty("routerSecurePort", "" + SocketUtils.findAvailableTcpPort())
        setupFakeServers()
        val prefix = System.getProperty("user.dir")
        tmpDeployDir = Files.createTempDirectory("ext-test-").toFile()
        File(tmpDeployDir, "conf").mkdirs()
        println()
        println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        println(">>>>>>>> Going to use tmp directory '" + tmpDeployDir + "' as traffic router deploy directory")
        println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
        println()
        System.setProperty("deploy.dir", tmpDeployDir!!.getAbsolutePath())
        System.setProperty("dns.zones.dir", "src/test/var/auto-zones")
        System.setProperty("cache.health.json.refresh.period", "10000")
        System.setProperty("cache.config.json.refresh.period", "10000")
        System.setProperty("dns.tcp.port", "" + SocketUtils.findAvailableTcpPort())
        System.setProperty("dns.udp.port", "" + SocketUtils.findAvailableUdpPort())
        System.setProperty("traffic_monitor.properties", "not_needed")
        val dbDirectory = File(tmpDeployDir, "db")
        dbDirectory.mkdir()
        LogManager.getLogger("org.eclipse.jetty").level = Level.WARN
        LogManager.getLogger("org.springframework").level = Level.WARN
        val consoleAppender = ConsoleAppender(PatternLayout("%d{ISO8601} [%-5p] %c{4}: %m%n"))
        LogManager.getRootLogger().addAppender(consoleAppender)
        LogManager.getRootLogger().level = Level.INFO

        // This one test the actual war that is output by the build process
        catalinaTrafficRouter = CatalinaTrafficRouter("src/main/conf/server.xml", "target/ROOT")

        // Uncomment this configuration for a lot more logging but could contain changes or temporary configuration which won't be part of the final build
        //catalinaTrafficRouter = new CatalinaTrafficRouter("src/main/conf/server.xml", "src/main/webapp");
        println("catalinaTrafficRouter: " + catalinaTrafficRouter.toString())
        catalinaTrafficRouter!!.start()
    }

    @AfterClass
    @Throws(LifecycleException::class, IOException::class)
    fun afterClass() {
        catalinaTrafficRouter!!.stop()
        httpDataServer!!.stop()
        tmpDeployDir!!.deleteOnExit()
        Files.walkFileTree(tmpDeployDir!!.toPath(), object : SimpleFileVisitor<Path>() {
            override fun visitFile(path: Path, attrs: BasicFileAttributes): FileVisitResult {
                path.toFile().delete()
                return FileVisitResult.CONTINUE
            }

            override fun postVisitDirectory(path: Path, e: IOException): FileVisitResult {
                path.toFile().delete()
                return FileVisitResult.CONTINUE
            }
        })
    }

    // The following is just a self signed certificate and key to use for testing
    // this is NOT private data from a CA
    const val HTTPS_TEST_CERT = "MIIDSjCCAjICCQD3t6XVBNkGMTANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJV" +
            "UzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEMMAoGA1UEChMDRm9vMRAw" +
            "DgYDVQQLEwdGb28gRGV2MRowGAYDVQQDFBEqLmZvby5leGFtcGxlLmNvbTAeFw0x" +
            "NjA5MTYyMTMzMzJaFw0yNjA5MTQyMTMzMzJaMGcxCzAJBgNVBAYTAlVTMQswCQYD" +
            "VQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQwwCgYDVQQKEwNGb28xEDAOBgNVBAsT" +
            "B0ZvbyBEZXYxGjAYBgNVBAMUESouZm9vLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG" +
            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCYjDRdkX1gl0ayYJmMJtrVJnPCEIypy6Obt" +
            "lIwjgPsevKHdMZlE+O1IgR4v3CwR1A/xKSh61Ru+bEggXBbyfSk7eT2v4l6GIN4B" +
            "aylN4jhZv3IFCjbks5xzM/Fs+PGW2hHNjZ79J6lqI6cl7bCkqcG6lsbfMVK8Y3ec" +
            "cQw+s9V7HMDMl83jt5i5t8X1eKFGgkrHwX02XHbY8OEzA75X1VQTvqtV4Azy/SZN" +
            "jpBcnrYKPptDzuvCVLVBl0sm+mu3cqsaGAteP5BSNJhCPUXT+v5FQxLPUVq3AwPF" +
            "1yIgduD/3UZzxl0RUgpWbHx9+Y8tkNweGbNKBdtpkgqm1dI1ZwIDAQABMA0GCSqG" +
            "SIb3DQEBBQUAA4IBAQBiovAGhnqfsab8LoUljaojLyaegw5sq5/tytpEmMl7wxda" +
            "KOxTCVpNLyNgy0l3XBCctp+QJUxqIFvidBmO4muVMmaJGfyBmBEYSIvtNDNDWIKC" +
            "KMYgY+UrWhjE9b/UwvD+k0lZ/+IdTn+wA4SjWdypOtjihuCJ8XFKmyyU5/LplX3n" +
            "HtFMI1k28H6jWY5umXqhjZg2iRspCANnFtIdVCtFTbCzK9fw3avREz7RBgH6Vg2M" +
            "CBaKjFfJobHedFMpYcNAvxDp19lWttLdYS6YNzznZEkTwQx+ryfNc0tteeHTAd5n" +
            "dRNQnAe374pvwYpALQWLBcsTYuxfIzTfTAWzR39r"

    // This is a PKCS1 formatted key which is the typical case for
    // keys created by clicking 'generate ssl keys' in Traffic Ops
    const val HTTPS_TEST_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEowIBAAKCAQEAqCYjDRdkX1gl0ayYJmMJtrVJnPCEIypy6ObtlIwjgPsevKHd\n" +
            "MZlE+O1IgR4v3CwR1A/xKSh61Ru+bEggXBbyfSk7eT2v4l6GIN4BaylN4jhZv3IF\n" +
            "Cjbks5xzM/Fs+PGW2hHNjZ79J6lqI6cl7bCkqcG6lsbfMVK8Y3eccQw+s9V7HMDM\n" +
            "l83jt5i5t8X1eKFGgkrHwX02XHbY8OEzA75X1VQTvqtV4Azy/SZNjpBcnrYKPptD\n" +
            "zuvCVLVBl0sm+mu3cqsaGAteP5BSNJhCPUXT+v5FQxLPUVq3AwPF1yIgduD/3UZz\n" +
            "xl0RUgpWbHx9+Y8tkNweGbNKBdtpkgqm1dI1ZwIDAQABAoIBABsDrYPv6ydKQSEz\n" +
            "imo4ZRoefAojtgb0TevPFgJUlWumbKS/mIrcZfFcJdbgo63Kwr6AJS2InFtajrhU\n" +
            "yiYhZanoEu8CkxxaNVBYen/d7e5XQUv5pIeklA+rJfMFaY2BOswkKhMDpQZXOH8r\n" +
            "3nMWew3u2uxYXQlOkoekctTSs8wuUFC7jPKlRrunDTBCBPZYkTyqHDov4k4NwoTX\n" +
            "0WMQeFZgXoKJAqcxSDdAGTHImIPK941oKlPHJxEAg6XiAmzJ7ipj8VS2WElu+7Fa\n" +
            "1SG1U1dD0lMn5oo+B4xw97EW0GzKqcAqOG/pyHy17rjjmEVOkCr/ntJdQVYYS0s9\n" +
            "+wpRTUkCgYEA2XuBSyfNiU6vslliZBarX6kCLXCfOObzatYR0XpMNSCf+mxfVKzz\n" +
            "ZWgsY6F6dE/twtJdhpdcnguZXGHXVitPJ5lCTLC14E+POiIItRaypcQZWmfMuWSg\n" +
            "SbIvWxlokS0liWGa1ENxDze80oSc7KwOdIKEzWh9e/dg4TmYJ45G4csCgYEAxe3j\n" +
            "b+DP3LvG5WUR9ya+Wtgh5doEwjUzqrqLJqCe0Idp/kM1rhcRTP3VgVS9izmeHEfy\n" +
            "kTwYGuvHSrWR9RDY8kODHd3MdZpv/HfW2hc4x9bHHmDGfoTrNKD61FvfshD7Um4O\n" +
            "LTWAXH1MYuRXEOdpyI34J8XA4xqSU4wVRW4AF1UCgYBYgpssKxbLOurmetpAQbmd\n" +
            "RPtN4vfqAJQwds7pogxB0vVIxbJGk9y6+JqYMa/UhnMNRvApRpC7AZ14q5knyJh+\n" +
            "VTFWZNSgZcC0uAUzLfmm3Rg0Yuo+yWUymQIM4VpdOzJ7pu2MVaY9u0Ftq+rxp1R6\n" +
            "tmO19UCcoyEaiIYUEyNl4QKBgQC50xsZ2Y4tpZoZmmdgi95hedNxcdvP3ZURcCve\n" +
            "ayRPkSLhFYabWIrkptfBoaaGxOR9lsrUsf/LnpsvuAI9e8DCysGZ07f2nbUP6g8s\n" +
            "GGs1q56sFZ2mAPK2KYD0yQDes/TQsgTbSwSlUPnbSpe3hhwZr7hQ1ue+EB9bEwSR\n" +
            "d7HcNQKBgA9g/ltyS8gwvP4PfVrwJLrmojJ4u2KW++PDngZTdMUC0GflbIE1qjPa\n" +
            "RKiKr0t5PB7LJNk9aih2suQhBf+XqBuPWceqzZP7Djxb3980d5JOtgqT1HmyJlqj\n" +
            "j/mOtWv+25AXx2IzbOo8KT2riNdbJR4lrFFPeGaUuTKcX0cUzsMC\n" +
            "-----END RSA PRIVATE KEY-----"

    // The following is just a self signed certificate and key to use for testing
    // this is NOT private data from a CA
    // *.http-and-https-test.thecdn.example.com
    //
    // openssl req -nodes -newkey rsa:2048 -keyout ~/tmp/http-and-https.key -out ~/tmp/http-and-https.csr
    //
    // openssl x509 -req -days 3650 -in ~/tmp/http-and-https.csr -signkey ~/tmp/http-and-https.key -out ~/tmp/http-and-https.crt
    const val HTTP_AND_HTTPS_TEST_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDjhGSGLMVtaY32\n" +
            "aS7aBogJCVmWNb6esx7+W6ug/wwYgwrsCL0nl+J6snPBOG4HoHHU5pKisHVYAbUi\n" +
            "3TUBgjeP/uCGxKIonjru5cbS7tRIoTqSX/PJOlm35i0sJ55A3UHZafH8C0xnSzQj\n" +
            "Ti9Evot58wCza/zfHKp/01Ig0M38+BhU7jpDzEgNEbYfUVpgAkES0JoJBAvrzqKB\n" +
            "IZHXtp9hMy6uG8cTOybFDZZGJfwfUpngWqQGfT2h91ah49gVbAlef//647EuW1Dw\n" +
            "X7PQKb0rc1bPYtlaVfeEZNb+e+52hs/B/hL2rXJ++G2t+2skahi5Kq7bcycQGjr+\n" +
            "OROkA5UbAgMBAAECggEBALqsif49Bc/752rianqhGUSw0zyX5Es6FJgGhw+VtEr4\n" +
            "WiHIGcs+p6icerVyo3TGhB92/6FUvzLyU7jDXxZZzVTsfzSUaaiCC0Cwby3qn2ro\n" +
            "PrKS3+efZLWqui2cZBA8eib08oMmkg2+eoztPYNeA/qPE2gjlltJnes7bAtYx2pi\n" +
            "aQK5stsynOWyxYdDdmqC7VJxCtC9sTmubaAQXHBBzrQnmMt7XzYsc6X/WhbWIFbs\n" +
            "CxvC6K0CSUD0DzPUz2eN8QERMQQZQMysq+DA73/G9Zrl4LFL4qLTooviVgzq1gjx\n" +
            "5yzKYR93CNk0HFIJzREw/FPm9xKa6tH5ZnwpV6FVRSECgYEA+EfzX/vWGqTWH05X\n" +
            "y1p1iNmNst9PbPVdJx/SqiitU0RsF+A2g1y/THEt67d6l4CD6OlsK/yTNHRr/dMm\n" +
            "L9B0SLVYUNGNnphl3WF10VQ2Y+80dRyWSbJpqty7L3P3uLOmkZRX1/9X254ryVEj\n" +
            "n6KmkKK056u7RZoQw1ZXMK8RkVUCgYEA6pcvCwJBgzIwc9LufIpLa7NurX249Bbp\n" +
            "9B9LYS1vfS2GYAypZfvIwqUi8jAjH2SIaVzI7q3mzocn+lV93ZuvU/dHjYs1VTC3\n" +
            "nW2G1sTk3nkSlrWnH0mDpkta9UK3/nD4gOmZmHD2rPyAvzj+RE3EAB0lzQGV9Squ\n" +
            "aztpg7BsTK8CgYEA68xZxhUFmLRob78V/png+qGzw+f2JQM6/0dn6hdL1cMr7dkR\n" +
            "rNzPCiiLdk0BbxWtMe1OwM/WdoEDd0OsBskxR0SDpe3/VFpklEZVgQM7zNmHtpn5\n" +
            "2fBKDu4oEL9Qy+hDEAwVCZ0GshucdkxLSvdMvhzpNwWQjF/v/7TmheQfCSkCgYBM\n" +
            "hdiAnNHF/B82CP5mfa4wia12xmYIqVjTm0m5f1q42JrWxgqUC9fnNnr5yZ4LZX3h\n" +
            "8LRSt0Ns50WxMSYHnftJRoZ+s4RIL8YVgl7TvBJ0R8Y6hzLmz9Iz8qzPCF6Aj1Vg\n" +
            "p9LEmUS+FPfiaLL4kO14pAlqoDPMb4nJzO2UWX5aXQKBgAmnvhj/aLcJnCJM0YnC\n" +
            "/aRWTF5Q3HQmPOHx5fQlw9+hCjQUkaoPL5JVs4/Z/dOj1RsWYHg23fGy78zNHkQi\n" +
            "zL6P2WpZ7pEpJbK4wobpfitzczKfNZROAzdJPDV4+ebtPHMkGA/ibN04AM2SWKTH\n" +
            "UoGXvsZbRbb+j3EptEHBiNiN\n" +
            "-----END PRIVATE KEY-----"
    const val HTTP_AND_HTTPS_TEST_CERT = "MIIDqjCCApICCQDx6373gd/QFDANBgkqhkiG9w0BAQsFADCBljELMAkGA1UEBhMC" +
            "VVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxFTATBgNVBAoM" +
            "DEh1YmNhcHMgUiBVczEZMBcGA1UECwwQSHViY2FwIFBvbGlzaGVyczExMC8GA1UE" +
            "AwwoKi5odHRwLWFuZC1odHRwcy10ZXN0LnRoZWNkbi5leGFtcGxlLmNvbTAeFw0x" +
            "NjA4MDkyMTI0NDdaFw0yNjA4MDcyMTI0NDdaMIGWMQswCQYDVQQGEwJVUzERMA8G" +
            "A1UECAwIQ29sb3JhZG8xDzANBgNVBAcMBkRlbnZlcjEVMBMGA1UECgwMSHViY2Fw" +
            "cyBSIFVzMRkwFwYDVQQLDBBIdWJjYXAgUG9saXNoZXJzMTEwLwYDVQQDDCgqLmh0" +
            "dHAtYW5kLWh0dHBzLXRlc3QudGhlY2RuLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG" +
            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA44RkhizFbWmN9mku2gaICQlZljW+nrMe/lur" +
            "oP8MGIMK7Ai9J5fierJzwThuB6Bx1OaSorB1WAG1It01AYI3j/7ghsSiKJ467uXG" +
            "0u7USKE6kl/zyTpZt+YtLCeeQN1B2Wnx/AtMZ0s0I04vRL6LefMAs2v83xyqf9NS" +
            "INDN/PgYVO46Q8xIDRG2H1FaYAJBEtCaCQQL686igSGR17afYTMurhvHEzsmxQ2W" +
            "RiX8H1KZ4FqkBn09ofdWoePYFWwJXn//+uOxLltQ8F+z0Cm9K3NWz2LZWlX3hGTW" +
            "/nvudobPwf4S9q1yfvhtrftrJGoYuSqu23MnEBo6/jkTpAOVGwIDAQABMA0GCSqG" +
            "SIb3DQEBCwUAA4IBAQBpO3jPVhDvFPJZJmzFbaC2vT/yq1oPtn9Z29bvkz9UTOc8" +
            "aItDK84KjbuUZ3i9ol1AWu6tWQRitfnxpkhKDEMXaOZq/HBMrz4XPHC+2Ez/+lOU" +
            "SmwAQHaaQMS20/9TAtNjIBvwphFpXXeT6Iz2NZl2EYEVdIfbQkTW0UsoFzBZGn3S" +
            "/0OXhd1lRXt0lH8glYEkL35FQJ0PCIM5W4mRJ50FKTI1x52xFY44ctEtGYkrGeWZ" +
            "4xYU0pTLKEYET0vKBHkjcvevI7dTd7caaWIXu4WG6ToVz8suTiKH49dMd3ev0qM7" +
            "qnx67ypmcnGqRRLxC6F2gnMx8B8sJ37QQlEYBMQo"

    // The following is just a self signed certificate and key to use for testing
    // this is NOT private data from a CA
    // *.http-to-https-test.thecdn.example.com
    //
    // openssl req -nodes -newkey rsa:2048 -keyout ~/tmp/http-to-https.key -out ~/tmp/http-to-https.csr
    //
    // openssl x509 -req -days 3650 -in ~/tmp/http-to-https.csr -signkey ~/tmp/http-to-https.key -out ~/tmp/http-to-https.crt
    const val HTTP_TO_HTTPS_TEST_KEY = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDKu4aRsrexzyck\n" +
            "+IxuotTSfvt2YLhrhFRscSLQdo56+RE402e8FuJ4DONwPRxbNdjL+E7elLg+onOf\n" +
            "gB9sYkzzFIy4CDp5qoGkencFNJrDwJ+KGxWzxTyPsy3rTGSx4hHj0o1AuE0k1Tgx\n" +
            "A8XWtG7UE20iV6Gj5bzSqDLOR/fvsQESSdFFHKArO0fQcd8Z3LVdczv+3To10Mhu\n" +
            "+zdltzjE7v4A38ewKVgFBk1BAOxc7y/ytP3iUH2YS99H3jB61Ej18e+VYe5oaw60\n" +
            "/4r2PG0FlXORxJuB9rC7OydXvu6fvOE6lmcImnyXUrBf8C+bHgO4CWG6thOVW4el\n" +
            "vOo8dFP3AgMBAAECggEAEFxr8swyiPYH2bL5WmBnvoki8B3EJGEskwfaYGqA+ymo\n" +
            "myZsg8BxDHE11bQI2s+QrH1gmBP2fo+Ltz6Wyp9wSFnLNXrshS8egVCk1FW3e77K\n" +
            "4VFoQfbT+WDjfs7OfZCaEwHGBogZKbTPcR011SsAmrrqns/lqp16zKFoYD9sofpJ\n" +
            "AZHL6Biu9PTfob0W8Co6thiii1xn+TEdc1ESDYdkYM5xsphrLoYyM7n1VyXRl31g\n" +
            "sewofW/ArF4K0Vl5iGygRKPw+Izqq4iCSqTzVr1T4Eh56k0cW0opOgww/LdybyGq\n" +
            "EqvczqHkj0sjHX9WKbTkNGAcymCUAVyaCf4g8Upn0QKBgQD7c8zBPhj1NO42I+yJ\n" +
            "+SkZKg24zudJb+ztjeBFg28Vg8n13xQIgHHMtIDaC8G/5vgrS0WFFVZuYTSLU2R3\n" +
            "b954H65c+L5N1mDAD3EDE73+xHfbm8dEeJVeGK59x1CgkGbLtgiaf/d466KhOiQj\n" +
            "xlsBEkByLIXfmrxXYZH54xD1GQKBgQDOZihiRKZ9oGUlGh4CWO/gh3RjrXhqxDES\n" +
            "9OzMrpEJQLe3Af1rHUHkL1ugjkykYwqD8AvKnsoJ+2Bbri5dtmTE0f6R3K5QP8vH\n" +
            "pShnFTxU6Q3/meDxwnIX6a5AfLXJsyxmVV1fmsD3UayN7lrAtWT4CNlicFrHUZJL\n" +
            "S18epmEjjwKBgGZyRpDQyQBWQVtjhYKtNfZfsNmDyq2b4U7jx+TqaL6+Q/Fdot7X\n" +
            "3gWF4R11Psn9w0x4TWmsSNuN1QeSwVL8DAqq9bJBUd+KoT5+zA9x4q3CxAaAUE5w\n" +
            "RoLg0W7DXvEcBBWpI5Y23s+wSUEg3AqLTRaBpioeQ6jXdTawtPW3cng5AoGBAK2X\n" +
            "nj+IHb9rN6aM4NB4nMfrJSjwrWaeu+eFt+Quri1qERoKwmlkohaY/id7h1p7Mkzl\n" +
            "iAVSp/rdQZ3aUYTf8sDXHZTwVmuIPIwdjG2mnqeLnApuEZNER1F1aOkz+nE6EQ3A\n" +
            "nlfagJGCT+7PmeSaq+ExECSK+s7I/JH3Qnk01l5hAoGAWSa7fzLS57XFTHTTYddt\n" +
            "tK5W6hlKwEb/tBnI8iLnWa+KhmTo/VPsc1C4rV3FqVFfMN6ZHMCEdG/Hq9vQdkQZ\n" +
            "35crLobjKIk5tlVzEbWxwl8EQez180r0O1VsRIiceIlzXRl3I17GeEKQHaORx/wS\n" +
            "PkZQNvkYw/OLHPViXWBGCsQ=\n" +
            "-----END PRIVATE KEY-----"
    const val HTTP_TO_HTTPS_TEST_CERT = "MIIDpjCCAo4CCQDLCWeLJrqPvDANBgkqhkiG9w0BAQsFADCBlDELMAkGA1UEBhMC" +
            "VVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxGDAWBgNVBAoM" +
            "D1Ntb2tlIEFuZCBGbGFtZTEaMBgGA1UECwwRU3BsaW50ZXIgVHJpbW1lcnMxKzAp" +
            "BgNVBAMMIiouaHR0cC10by1odHRwcy50aGVjZG4uZXhhbXBsZS5jb20wHhcNMTYw" +
            "ODA5MTgyMDA1WhcNMjYwODA3MTgyMDA1WjCBlDELMAkGA1UEBhMCVVMxETAPBgNV" +
            "BAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxGDAWBgNVBAoMD1Ntb2tlIEFu" +
            "ZCBGbGFtZTEaMBgGA1UECwwRU3BsaW50ZXIgVHJpbW1lcnMxKzApBgNVBAMMIiou" +
            "aHR0cC10by1odHRwcy50aGVjZG4uZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEB" +
            "AQUAA4IBDwAwggEKAoIBAQDKu4aRsrexzyck+IxuotTSfvt2YLhrhFRscSLQdo56" +
            "+RE402e8FuJ4DONwPRxbNdjL+E7elLg+onOfgB9sYkzzFIy4CDp5qoGkencFNJrD" +
            "wJ+KGxWzxTyPsy3rTGSx4hHj0o1AuE0k1TgxA8XWtG7UE20iV6Gj5bzSqDLOR/fv" +
            "sQESSdFFHKArO0fQcd8Z3LVdczv+3To10Mhu+zdltzjE7v4A38ewKVgFBk1BAOxc" +
            "7y/ytP3iUH2YS99H3jB61Ej18e+VYe5oaw60/4r2PG0FlXORxJuB9rC7OydXvu6f" +
            "vOE6lmcImnyXUrBf8C+bHgO4CWG6thOVW4elvOo8dFP3AgMBAAEwDQYJKoZIhvcN" +
            "AQELBQADggEBAKREwCYFiz858Iqsf+m/rkQErTVeSUPg6KSlDDknVI/x+x0uCwXN" +
            "OgGo5s2S6Ec0V8hd9PrADasCDtAGaLJ2giNEyv/0iZRcTfR2mfnKClZcVbEgvhqt" +
            "1e6oQ1ybKw+fsvSWOu8h30CiKjct4+gWjoSbyVgmHFSBdKvZJwice2ewi2SE+H4y" +
            "ekPD6BptIJQc6UfFE4ZuO7S7ajroWU7dVeI495Q8BQ89LWPgUwc/a90VrICAT9bB" +
            "VM+SiCpEFStMFlz/bEkm9goZJKroaPwXVf75hEicAaAPFs5zlQpfh4LOF+Gk0P/G" +
            "WNmQ5qbTdEyM1vxgM/4anoOFfaHhB4Pk8T4="
}