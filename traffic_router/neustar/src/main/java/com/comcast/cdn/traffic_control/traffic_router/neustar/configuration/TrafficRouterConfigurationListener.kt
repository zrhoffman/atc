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
package com.comcast.cdn.traffic_control.traffic_router.neustar.configuration

import com.comcast.cdn.traffic_control.traffic_router.configuration.ConfigurationListener

class TrafficRouterConfigurationListener : ConfigurationListener {
    private val logger: Logger? = Logger.getLogger(TrafficRouterConfigurationListener::class.java)

    @Autowired
    private val environment: Environment? = null

    @Autowired
    var scheduledExecutorService: ScheduledExecutorService? = null

    @Autowired
    var serviceRefresher: ServiceRefresher? = null
    private var scheduledFuture: ScheduledFuture<*>? = null
    @Override
    fun configurationChanged() {
        var restarting = false
        if (scheduledFuture != null) {
            restarting = true
            scheduledFuture.cancel(true)
            while (!scheduledFuture.isDone()) {
                try {
                    Thread.sleep(100L)
                } catch (e: InterruptedException) {
                    // ignore
                }
            }
        }
        val fixedRate: Long = environment.getProperty("neustar.polling.interval", Long::class.java, 86400000L)
        scheduledFuture =
            scheduledExecutorService.scheduleAtFixedRate(serviceRefresher, 0L, fixedRate, TimeUnit.MILLISECONDS)
        val prefix = if (restarting) "Restarting" else "Starting"
        logger.warn("$prefix Neustar remote database refresher at rate $fixedRate msec")
    }
}