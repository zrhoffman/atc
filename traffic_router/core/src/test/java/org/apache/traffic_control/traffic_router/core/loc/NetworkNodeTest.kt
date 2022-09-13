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
package org.apache.traffic_control.traffic_router.core.loc

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.common.net.InetAddresses
import java.io.*

org.apache.logging.log4j.LogManager
import org.apache.tomcat.util.net.SSLImplementation
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.jsse.JSSESupport
import org.apache.tomcat.util.net.SSLUtil
import secure.KeyManagerTest.TestSNIServerName
import secure.CertificateDataConverterTest
import org.apache.traffic_control.traffic_router.protocol.RouterSslImplementationimport

org.hamcrest.MatcherAssertimport org.hamcrest.Matchersimport org.junit.*import java.io.*
import java.lang.Exceptionimport

java.util.ArrayList
class NetworkNodeTest {
    private val netMap: MutableMap<String?, MutableList<String?>?>? = HashMap()
    private val deepNetMap: MutableMap<String?, MutableList<String?>?>? = HashMap()
    private var root: NetworkNode? = null
    private var deepRoot: NetworkNode? = null
    @Before
    @Throws(Exception::class)
    fun setUp() {
        root = setUp("czmap.json", false)
        deepRoot = setUp("dczmap.json", true)
    }

    @Throws(Exception::class)
    private fun setUp(filename: String?, useDeep: Boolean): NetworkNode? {
        val testNetMap = if (useDeep) deepNetMap else netMap
        val file = File(javaClass.classLoader.getResource(filename).toURI())
        val nn: NetworkNode = NetworkNode.Companion.generateTree(file, false, useDeep)
        val mapper = ObjectMapper()
        val jsonNode = mapper.readTree(file)
        val czKey = if (useDeep) "deepCoverageZones" else "coverageZones"
        val coverageZones = jsonNode[czKey]
        val networkIter = coverageZones.fieldNames()
        while (networkIter.hasNext()) {
            val loc = networkIter.next()
            val locData = coverageZones[loc]
            for (networkType in arrayOf<String?>("network", "network6")) {
                val networks = locData[networkType]
                val network = networks[0].asText().split("/".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[0]
                var ip = InetAddresses.forString(network)
                ip = InetAddresses.increment(ip)
                if (!testNetMap.containsKey(loc)) {
                    testNetMap[loc] = ArrayList()
                }
                val addressList = testNetMap.get(loc)
                addressList.add(InetAddresses.toAddrString(ip))
                testNetMap[loc] = addressList
            }
        }
        return nn
    }

    @Test
    fun testIps() {
        try {
            for (location in netMap.keys) {
                for (address in netMap.get(location)) {
                    val nn = root.getNetwork(address)
                    Assert.assertNotNull(nn)
                    val loc = nn.getLoc()
                    Assert.assertEquals(loc, location)
                    LOGGER.info(String.format("result for ip=%s: %s", address, loc))
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @Test
    fun testNetworkNodePerformance() {
        testNetworkNodePerformance(root, netMap)
    }

    @Test
    fun testDeepNetworkNodePerformance() {
        testNetworkNodePerformance(deepRoot, deepNetMap)
    }

    private fun testNetworkNodePerformance(testRoot: NetworkNode?, testNetMap: MutableMap<String?, MutableList<String?>?>?) {
        val iterations = 100000
        val startTime = System.currentTimeMillis()
        val nnTPS = System.getProperty("nnTPS", "12000").toLong()
        for (i in 0 until iterations) {
            for (location in testNetMap.keys) {
                try {
                    for (address in testNetMap.get(location)) {
                        val nn = testRoot.getNetwork(address)
                    }
                } catch (e: NetworkNodeException) {
                    e.printStackTrace()
                }
            }
        }
        val runTime = System.currentTimeMillis() - startTime
        val tps = iterations / runTime * 1000
        MatcherAssert.assertThat(tps, Matchers.greaterThanOrEqualTo(nnTPS))
    }

    companion object {
        private val LOGGER = LogManager.getLogger(NetworkNodeTest::class.java)
    }
}