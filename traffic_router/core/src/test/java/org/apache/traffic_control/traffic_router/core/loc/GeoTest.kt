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

import org.apache.traffic_control.traffic_router.core.TestBase
import org.apache.traffic_control.traffic_router.core.util.IntegrationTest

org.apache.logging.log4j.LogManager
import org.apache.tomcat.util.net.SSLImplementation
import org.apache.tomcat.util.net.SSLSupport
import org.apache.tomcat.util.net.jsse.JSSESupport
import org.apache.tomcat.util.net.SSLUtil
import secure.KeyManagerTest.TestSNIServerName
import secure.CertificateDataConverterTest
import org.apache.traffic_control.traffic_router.protocol.RouterSslImplementationimport

org.junit.*import org.junit.experimental.categories.Categoryimport

org.springframework.context.ApplicationContextimport java.lang.Exception
@Category(IntegrationTest::class)
class GeoTest {
    private var geolocationDatabaseUpdater: GeolocationDatabaseUpdater? = null
    private var maxmindGeolocationService: MaxmindGeolocationService? = null
    @Before
    @Throws(Exception::class)
    fun setUp() {
        geolocationDatabaseUpdater = context.getBean("geolocationDatabaseUpdater") as GeolocationDatabaseUpdater
        maxmindGeolocationService = context.getBean("maxmindGeolocationService") as MaxmindGeolocationService
        geolocationDatabaseUpdater.loadDatabase()
        while (!geolocationDatabaseUpdater.isLoaded()) {
            LOGGER.info("Waiting for a valid Maxmind database before proceeding")
            Thread.sleep(1000)
        }
    }

    @Test
    fun testIps() {
        try {
            val testips = arrayOf<Array<String?>?>(arrayOf("40.40.40.40", "cache-group-1"))
            for (i in testips.indices) {
                val location = maxmindGeolocationService.location(testips[i].get(0))
                Assert.assertNotNull(location)
                val loc = location.toString()
                LOGGER.info(String.format("result for ip=%s: %s\n", testips[i], loc))
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    companion object {
        private val LOGGER = LogManager.getLogger(GeoTest::class.java)
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