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
package com.comcast.cdn.traffic_control.traffic_router.core.util

import com.comcast.cdn.traffic_control.traffic_router.core.TestBase
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringRegistry
import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcherTest
import com.fasterxml.jackson.databind.node.ObjectNode
import org.apache.log4j.Logger
import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.experimental.categories.Category
import org.springframework.context.ApplicationContext
import java.nio.file.Files
import java.nio.file.Paths

@Category(IntegrationTest::class)
class AbstractResourceWatcherTest {
    private var federationsWatcher: FederationsWatcher? = null
    private var steeringWatcher: SteeringWatcher? = null
    private var trafficRouterManager: TrafficRouterManager? = null
    private var steeringRegistry: SteeringRegistry? = null
    private var oldFedUrl: String? = null

    @Before
    @Throws(InterruptedException::class)
    fun setUp() {
        federationsWatcher = context.getBean("federationsWatcher") as FederationsWatcher
        steeringWatcher = context.getBean("steeringWatcher") as SteeringWatcher
        steeringRegistry = context.getBean("steeringRegistry") as SteeringRegistry
        trafficRouterManager = context.getBean("trafficRouterManager") as TrafficRouterManager
        trafficRouterManager.getTrafficRouter().setApplicationContext(context)
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        val cacheRegister = trafficRouter.cacheRegister
        var config = cacheRegister.config
        if (config[federationsWatcher.getWatcherConfigPrefix() + ".polling.url"] != null) {
            oldFedUrl = config[federationsWatcher.getWatcherConfigPrefix() + ".polling.url"].asText()
            config = (config as ObjectNode).remove(federationsWatcher.getWatcherConfigPrefix() + ".polling.url")
            federationsWatcher.trafficOpsUtils.setConfig(config)
            federationsWatcher.configure(config)
        }
        while (!federationsWatcher.isLoaded()) {
            LOGGER.info("Waiting for a valid federations database before proceeding")
            Thread.sleep(1000)
        }
        while (!steeringWatcher.isLoaded()) {
            LOGGER.info("Waiting for a valid steering database before proceeding")
            Thread.sleep(1000)
        }
    }

    @After
    fun tearDown() {
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        val cacheRegister = trafficRouter.cacheRegister
        var config = cacheRegister.config
        config = if (oldFedUrl != null && !oldFedUrl.isEmpty()) {
            (config as ObjectNode).put(federationsWatcher.getWatcherConfigPrefix() + ".polling.url", oldFedUrl)
        } else {
            (config as ObjectNode).remove(federationsWatcher.getWatcherConfigPrefix() + ".polling.url")
        }
        federationsWatcher.trafficOpsUtils.setConfig(config)
        federationsWatcher.configure(config)
        MatcherAssert.assertThat(
            federationsWatcher.getDataBaseURL(),
            Matchers.endsWith(
                FederationsWatcher.Companion.DEFAULT_FEDERATION_DATA_URL.split("api".toRegex()).toTypedArray().get(1)
            )
        )
    }

    @Test
    fun testWatchers() {
        val trafficRouter = trafficRouterManager.getTrafficRouter()
        val cacheRegister = trafficRouter.cacheRegister
        var config = cacheRegister.config
        Assert.assertNull(config[federationsWatcher.getWatcherConfigPrefix() + ".polling.url"])
        MatcherAssert.assertThat(
            federationsWatcher.getDataBaseURL(),
            Matchers.endsWith(
                FederationsWatcher.Companion.DEFAULT_FEDERATION_DATA_URL.split("api".toRegex()).toTypedArray().get(1)
            )
        )
        MatcherAssert.assertThat(
            steeringWatcher.getDataBaseURL(),
            Matchers.endsWith(
                SteeringWatcher.Companion.DEFAULT_STEERING_DATA_URL.split("api".toRegex()).toTypedArray().get(1)
            )
        )
        val newFedsUrl = "https://\${toHostname}/api/3.0/notAFederationsEndpoint"
        config = (config as ObjectNode).put(federationsWatcher.getWatcherConfigPrefix() + ".polling.url", newFedsUrl)
        federationsWatcher.trafficOpsUtils.setConfig(config)
        federationsWatcher.configure(config)
        config = cacheRegister.config
        MatcherAssert.assertThat(
            config[federationsWatcher.getWatcherConfigPrefix() + ".polling.url"].asText(),
            Matchers.endsWith("api/3.0/notAFederationsEndpoint")
        )
        MatcherAssert.assertThat(
            federationsWatcher.getDataBaseURL(),
            Matchers.endsWith("api/3.0/notAFederationsEndpoint")
        )
    }

    companion object {
        private val LOGGER = Logger.getLogger(AbstractResourceWatcherTest::class.java)
        private var context: ApplicationContext? = null

        @BeforeClass
        fun setUpBeforeClass() {
            MatcherAssert.assertThat(
                "Copy core/src/main/conf/traffic_monitor.properties to core/src/test/conf and set 'traffic_monitor.bootstrap.hosts' to a real traffic monitor",
                Files.exists(Paths.get(TestBase.monitorPropertiesPath)),
                Matchers.equalTo(true)
            )
            context = TestBase.getContext()
        }
    }
}