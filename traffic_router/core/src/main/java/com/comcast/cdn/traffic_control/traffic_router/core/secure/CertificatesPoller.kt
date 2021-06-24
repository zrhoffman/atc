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
package com.comcast.cdn.traffic_control.traffic_router.core.secure

import com.comcast.cdn.traffic_control.traffic_router.configuration.ConfigurationListener
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.secure.CertificatesPoller
import com.comcast.cdn.traffic_control.traffic_router.shared.CertificateData
import org.apache.log4j.Logger
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.env.Environment
import java.util.concurrent.BlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class CertificatesPoller : ConfigurationListener {
    private val executor: ScheduledExecutorService?
    private var future: ScheduledFuture<*>? = null
    private var certificatesClient: CertificatesClient? = null
    private var pollingInterval = defaultFixedRate
    private var certificatesQueue: BlockingQueue<MutableList<CertificateData?>?>? = null
    private var lastFetchedData: MutableList<CertificateData?>? = ArrayList()
    private var trafficRouterManager: TrafficRouterManager? = null

    @Autowired
    private val environment: Environment? = null
    fun getEnvironmentPollingInterval(): Long? {
        if (environment == null) {
            LOGGER.warn("Could not find Environment object!")
        }
        return try {
            val value = environment.getProperty(intervalProperty, Long::class.java)
            if (value == null) {
                LOGGER.info("No custom value for " + intervalProperty)
            }
            value
        } catch (e: Exception) {
            LOGGER.warn("Failed to get value of " + intervalProperty + ": " + e.message)
            null
        }
    }

    fun start() {
        val runnable = label@ Runnable {
            try {
                trafficRouterManager.trackEvent("lastHttpsCertificatesCheck")
                val certificateDataList = certificatesClient.refreshData() ?: return@label
                if (lastFetchedData != certificateDataList) {
                    certificatesQueue.put(certificateDataList)
                    lastFetchedData = certificateDataList
                } else {
                    certificatesQueue.put(lastFetchedData)
                }
            } catch (t: Throwable) {
                LOGGER.warn("Failed to refresh certificate data: " + t.javaClass.canonicalName + " " + t.message, t)
            }
        }
        val customFixedRate = getEnvironmentPollingInterval()
        if (customFixedRate == null) {
            LOGGER.info("Using default fixed rate polling interval $pollingInterval msec")
        } else {
            LOGGER.info("Using custom fixed rate polling interval $customFixedRate msec")
            pollingInterval = customFixedRate
        }
        future = executor.scheduleWithFixedDelay(runnable, 0, pollingInterval, TimeUnit.MILLISECONDS)
        LOGGER.info("Polling for certificates every $pollingInterval msec")
    }

    fun stop() {
        if (future != null) {
            future.cancel(false)
        }
    }

    fun destroy() {
        certificatesClient.setShutdown(true)
        executor.shutdownNow()
    }

    fun setCertificatesClient(certificatesClient: CertificatesClient?) {
        this.certificatesClient = certificatesClient
    }

    private fun futureIsDone(): Boolean {
        return future == null || future.isDone() || future.isCancelled()
    }

    fun restart() {
        stop()
        while (!futureIsDone()) {
            try {
                Thread.sleep(250L)
            } catch (e: InterruptedException) {
                LOGGER.info("Interrupted sleep while waiting for certificate poller future to finish")
            }
        }
        start()
    }

    fun getPollingInterval(): Long {
        return pollingInterval
    }

    override fun configurationChanged() {
        restart()
    }

    fun getCertificatesQueue(): BlockingQueue<MutableList<CertificateData?>?>? {
        return certificatesQueue
    }

    fun setCertificatesQueue(certificatesQueue: BlockingQueue<MutableList<CertificateData?>?>?) {
        this.certificatesQueue = certificatesQueue
    }

    fun getTrafficRouterManager(): TrafficRouterManager? {
        return trafficRouterManager
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    companion object {
        private val LOGGER = Logger.getLogger(CertificatesPoller::class.java)
        private const val defaultFixedRate = 3600 * 1000L
        private val intervalProperty: String? = "certificates.polling.interval"
    }

    init {
        executor = Executors.newSingleThreadScheduledExecutor()
    }
}