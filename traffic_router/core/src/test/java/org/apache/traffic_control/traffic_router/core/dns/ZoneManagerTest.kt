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
package org.apache.traffic_control.traffic_router.core.dns

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.common.net.InetAddresses
import org.apache.traffic_control.traffic_router.core.TestBase
import org.apache.traffic_control.traffic_router.core.edge.Node.IPVersions
import org.apache.traffic_control.traffic_router.core.router.TrafficRouterManager
import org.apache.traffic_control.traffic_router.core.util.IntegrationTest
import java.io.*
import java.net.InetAddress

org.hamcrest.MatcherAssertimport org.hamcrest.core.IsCollectionContainingimport org.junit.*import org.junit.experimental.categories.Category

import org.springframework.context.ApplicationContextimport org.xbill.DNS.*import java.io.*
import java.lang.Exceptionimport

java.math.BigInteger
@Category(IntegrationTest::class)
class ZoneManagerTest {
    private var trafficRouterManager: TrafficRouterManager? = null
    private val netMap: MutableMap<String?, InetAddress?>? = HashMap()
    @Before
    @Throws(Exception::class)
    fun setUp() {
        trafficRouterManager = context.getBean("trafficRouterManager") as TrafficRouterManager
        trafficRouterManager.getTrafficRouter().setApplicationContext(context)
        val file = File("src/test/resources/czmap.json")
        val mapper = ObjectMapper()
        val jsonNode = mapper.readTree(file)
        val coverageZones = jsonNode["coverageZones"]
        val czIter = coverageZones.fieldNames()
        while (czIter.hasNext()) {
            val loc = czIter.next()
            val locData = coverageZones[loc]
            val networks = locData["network"]
            val network = networks[0].asText().split("/".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[0]
            var ip = InetAddresses.forString(network)
            ip = InetAddresses.increment(ip)
            netMap[loc] = ip
        }
    }

    @Test
    @Throws(TextParseException::class)
    fun testDynamicZoneCache() {
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        val cacheRegister = trafficRouter.cacheRegister
        val zoneManager = trafficRouter.zoneManager
        for (ds in cacheRegister.deliveryServices.values) {
            if (!ds.isDns) {
                continue
            }
            val domain = ds.domain
            val edgeName = Name(ds.routingName + "." + domain + ".")
            for (source in netMap.values) {
                val location = trafficRouter.getCoverageZoneCacheLocation(source.getHostAddress(), ds, IPVersions.IPV4ONLY)
                val caches = trafficRouter.selectCachesByCZ(ds, location, IPVersions.IPV4ONLY) ?: continue
                val builder = DNSAccessRecord.Builder(1, source)
                val zones: MutableSet<Zone?> = HashSet()
                val maxDnsIps = ds.maxDnsIps
                var combinations: Long = 1
                if (maxDnsIps > 0 && !trafficRouter.isConsistentDNSRouting && caches.size > maxDnsIps) {
                    val top = fact(caches.size)
                    val f = fact(caches.size - maxDnsIps)
                    val s = fact(maxDnsIps)
                    combinations = top.divide(f.multiply(s)).toLong()
                    var c = 0
                    while (c < combinations * 100) {
                        val zone = trafficRouter.getZone(edgeName, Type.A, source, true, builder) // this should load the zone into the dynamicZoneCache if not already there
                        Assert.assertNotNull(zone)
                        zones.add(zone)
                        c++
                    }
                }
                val cacheStats = zoneManager.dynamicCacheStats
                for (j in 0..combinations * 100) {
                    val missCount = cacheStats.missCount()
                    val zone = trafficRouter.getZone(edgeName, Type.A, source, true, builder)
                    Assert.assertNotNull(zone)
                    Assert.assertEquals(missCount, cacheStats.missCount()) // should always be a cache hit so these should remain the same
                    if (!zones.isEmpty()) {
                        MatcherAssert.assertThat(zones, IsCollectionContaining.hasItem(zone))
                        Assert.assertTrue(zones.contains(zone))
                    }
                }
            }
        }
    }

    private fun fact(n: Int): BigInteger? {
        var p: BigInteger? = BigInteger("1")
        for (c in n downTo 1) {
            p = p.multiply(BigInteger.valueOf(c))
        }
        return p
    }

    companion object {
        private var context: ApplicationContext? = null
        @BeforeClass
        @Throws(Exception::class)
        fun setUpBeforeClass() {
            TestBase.setupFakeServers()
            context = TestBase.getContext()
        }

        @AfterClass
        @Throws(Exception::class)
        fun tearDown() {
            TestBase.tearDownFakeServers()
        }
    }
}