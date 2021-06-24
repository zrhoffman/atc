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
package com.comcast.cdn.traffic_control.traffic_router.core.monitor

import com.comcast.cdn.traffic_control.traffic_router.core.config.ConfigHandler
import com.comcast.cdn.traffic_control.traffic_router.core.monitor.TrafficMonitorWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractUpdatable
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.comcast.cdn.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import org.springframework.context.ApplicationListener
import org.springframework.context.event.ApplicationContextEvent
import org.springframework.context.event.ContextClosedEvent
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.net.URI
import java.net.UnknownHostException
import java.nio.file.Path
import java.util.Arrays
import java.util.Properties

class TrafficMonitorWatcher : ApplicationListener<ApplicationContextEvent?> {
    private var stateUrl: String? = null
    private var configUrl: String? = null
    private var monitorHosts: String? = null
    private var pollingInterval = 5000
    private var lastHostAttempt: Long = 0
    private var reloadPeriod = (60 * 1000).toLong()
    private var configHandler: ConfigHandler? = null
    private var trafficRouterManager: TrafficRouterManager? = null
    private var statusFile: String? = null
    private var statusRefreshPeriod = 0
    private var configFile: String? = null
    private var configRefreshPeriod = 0
    private var monitorProperties: String? = null
    private var crUpdater: PeriodicResourceUpdater? = null
    private var stateUpdater: PeriodicResourceUpdater? = null
    private var propertiesDirectory: Path? = null
    private var databasesDirectory: Path? = null
    var stateHandler: AbstractUpdatable? = object : AbstractUpdatable() {
        override fun toString(): String? {
            return "status listener"
        }

        @Synchronized
        override fun update(jsonStr: String?): Boolean {
            try {
                val mapper = ObjectMapper()
                return trafficRouterManager.setState(mapper.readTree(jsonStr))
            } catch (e: JsonProcessingException) {
                LOGGER.warn("problem with json: ", e)
            } catch (e: IOException) {
                LOGGER.warn(e, e)
            }
            return false
        }

        override fun noChange(): Boolean {
            try {
                trafficRouterManager.setState(null)
            } catch (e: UnknownHostException) {
                LOGGER.warn("UnknownHostException: ", e)
            }
            return false
        }
    }

    fun destroy() {
        if (crUpdater != null) {
            crUpdater.destroy()
        }
        if (stateUpdater != null) {
            stateUpdater.destroy()
        }
    }

    fun init() {
        val crHandler: AbstractUpdatable = object : AbstractUpdatable() {
            override fun update(configStr: String?): Boolean {
                try {
                    try {
                        return configHandler.processConfig(configStr)
                    } catch (e: JsonUtilsException) {
                        LOGGER.warn(e, e)
                    }
                } catch (e: IOException) {
                    LOGGER.warn("error on config update", e)
                }
                return false
            }

            override fun toString(): String? {
                return "config listener"
            }

            override fun noChange(): Boolean {
                try {
                    configHandler.processConfig(null)
                } catch (e: Exception) {
                    LOGGER.warn(e, e)
                }
                return false
            }

            override fun complete() {
                if (!isLocalConfig() && !isBootstrapped()) {
                    setBootstrapped(true)
                }
            }

            override fun cancelUpdate() {
                configHandler.cancelProcessConfig()
            }
        }
        processConfig()
        crUpdater = PeriodicResourceUpdater(
            crHandler,
            TrafficMonitorResourceUrl(this, configUrl),
            databasesDirectory.resolve(configFile).toString(),
            configRefreshPeriod,
            true
        )
        crUpdater.init()
        stateUpdater = PeriodicResourceUpdater(
            stateHandler,
            TrafficMonitorResourceUrl(this, stateUrl),
            databasesDirectory.resolve(statusFile).toString(),
            statusRefreshPeriod,
            true
        )
        stateUpdater.init()
    }

    override fun onApplicationEvent(event: ApplicationContextEvent?) {
        if (event is ContextClosedEvent) {
            crUpdater.destroy()
            stateUpdater.destroy()
        }
    }

    fun getStateUrl(): String? {
        return stateUrl
    }

    fun setStateUrl(stateUrl: String?) {
        this.stateUrl = stateUrl
    }

    fun getConfigUrl(): String? {
        return configUrl
    }

    fun setConfigUrl(configUrl: String?) {
        this.configUrl = configUrl
    }

    fun setPollingInterval(pollingInterval: Int) {
        this.pollingInterval = pollingInterval
    }

    fun getPollingInterval(): Int {
        return pollingInterval
    }

    fun getConfigHandler(): ConfigHandler? {
        return configHandler
    }

    fun setConfigHandler(configHandler: ConfigHandler?) {
        this.configHandler = configHandler
    }

    fun getStatusFile(): String? {
        return statusFile
    }

    fun setStatusFile(statusFile: String?) {
        this.statusFile = statusFile
    }

    fun getStatusRefreshPeriod(): Int {
        return statusRefreshPeriod
    }

    fun setStatusRefreshPeriod(statusRefreshPeriod: Int) {
        this.statusRefreshPeriod = statusRefreshPeriod
    }

    fun getConfigFile(): String? {
        return configFile
    }

    fun setConfigFile(configFile: String?) {
        this.configFile = configFile
    }

    fun getConfigRefreshPeriod(): Int {
        return configRefreshPeriod
    }

    fun setConfigRefreshPeriod(configRefreshPeriod: Int) {
        this.configRefreshPeriod = configRefreshPeriod
    }

    fun getTrafficRouterManager(): TrafficRouterManager? {
        return trafficRouterManager
    }

    fun setTrafficRouterManager(router: TrafficRouterManager?) {
        trafficRouterManager = router
    }

    fun setMonitorProperties(monitorProperties: String?) {
        this.monitorProperties = monitorProperties
    }

    fun setMonitorHosts(monitorHosts: String?) {
        this.monitorHosts = monitorHosts
    }

    fun getHosts(): Array<String?>? {
        processConfig()
        return hosts
    }

    private fun processConfig() {
        val now = System.currentTimeMillis()
        if (now < lastHostAttempt + reloadPeriod) {
            return
        }
        lastHostAttempt = now
        try {
            val trafficMonitorConfigFile: File
            trafficMonitorConfigFile = if (monitorProperties.matches("^\\w+:.*")) {
                File(URI(monitorProperties))
            } else {
                File(monitorProperties)
            }
            val props = Properties()
            if (trafficMonitorConfigFile.exists()) {
                LOGGER.info("Loading properties from " + trafficMonitorConfigFile.absolutePath)
                FileInputStream(trafficMonitorConfigFile).use { configStream -> props.load(configStream) }
            } else {
                LOGGER.warn("Cannot load traffic monitor properties file " + trafficMonitorConfigFile.absolutePath + " file not found!")
            }
            var localConfig =
                java.lang.Boolean.parseBoolean(props.getProperty("traffic_monitor.bootstrap.local", "false"))
            var localEnvString = System.getenv("TRAFFIC_MONITOR_BOOTSTRAP_LOCAL")
            if (localEnvString != null) {
                localEnvString = localEnvString.toLowerCase()
            }
            if ("true" == localEnvString || "false" == localEnvString) {
                localConfig = java.lang.Boolean.parseBoolean(localEnvString)
            }
            if (localConfig != isLocalConfig()) {
                LOGGER.info("traffic_monitor.bootstrap.local changed to: $localConfig")
                setLocalConfig(localConfig)
            }
            if (localConfig || !isBootstrapped()) {
                var hostList = System.getenv("TRAFFIC_MONITOR_HOSTS")
                if (hostList != null && !hostList.isEmpty()) {
                    LOGGER.warn("hostlist initialized to '$hostList' from env var 'TRAFFIC_MONITOR_HOSTS'")
                }
                if (hostList == null || hostList.isEmpty()) {
                    hostList = props.getProperty("traffic_monitor.bootstrap.hosts")
                }
                if (hostList == null || hostList.isEmpty()) {
                    if (!trafficMonitorConfigFile.exists()) {
                        LOGGER.fatal(trafficMonitorConfigFile.absolutePath + " does not exist and the environment variable 'TRAFFIC_MONITOR_HOSTS' was not found")
                    } else {
                        LOGGER.error("Cannot determine Traffic Monitor hosts from property 'traffic_monitor.bootstrap.hosts' in config file " + trafficMonitorConfigFile.absolutePath)
                    }
                } else {
                    setHosts(
                        if (hostList.contains(";")) hostList.split(";".toRegex()).toTypedArray() else arrayOf(
                            hostList
                        )
                    )
                }
            } else if (!isLocalConfig() && isBootstrapped()) {
                synchronized(monitorSync) {
                    if (!onlineMonitors.isEmpty()) {
                        setHosts(onlineMonitors.toTypedArray())
                    }
                }
            }
            val reloadPeriodStr = props.getProperty("traffic_monitor.properties.reload.period")
            if (reloadPeriodStr != null) {
                val newReloadPeriod = reloadPeriodStr.toInt().toLong()
                if (newReloadPeriod != reloadPeriod) {
                    reloadPeriod = newReloadPeriod
                    LOGGER.info("traffic_monitor.properties.reload.period changed to: $reloadPeriod")
                }
            }
        } catch (e: Exception) {
            LOGGER.warn(e, e)
        }
        if (hosts == null) {
            hosts = monitorHosts.split(";".toRegex()).toTypedArray()
        }
    }

    fun getPropertiesDirectory(): Path? {
        return propertiesDirectory
    }

    fun setPropertiesDirectory(propertiesDirectory: Path?) {
        this.propertiesDirectory = propertiesDirectory
    }

    fun getDatabasesDirectory(): Path? {
        return databasesDirectory
    }

    fun setDatabasesDirectory(databasesDirectory: Path?) {
        this.databasesDirectory = databasesDirectory
    }

    companion object {
        private val LOGGER = Logger.getLogger(TrafficMonitorWatcher::class.java)
        private var bootstrapped = false
        private var localConfig = false
        private var onlineMonitors: MutableList<String?>? = ArrayList()
        private var hosts: Array<String?>?
        private val hostSync: Any? = Any()
        private val monitorSync: Any? = Any()
        fun setHosts(newHosts: Array<String?>?) {
            synchronized(hostSync) {
                if (hosts == null || hosts.size == 0) {
                    hosts = newHosts
                    LOGGER.info("traffic_monitor.bootstrap.hosts: " + Arrays.toString(hosts))
                } else if (!Arrays.asList(*hosts).containsAll(Arrays.asList(*newHosts))
                    || !Arrays.asList(*newHosts).containsAll(Arrays.asList(*hosts))
                ) {
                    hosts = newHosts
                    LOGGER.info("traffic_monitor.bootstrap.hosts changed to: " + Arrays.toString(hosts))
                }
            }
        }

        fun isBootstrapped(): Boolean {
            return bootstrapped
        }

        private fun setBootstrapped(bootstrapped: Boolean) {
            Companion.bootstrapped = bootstrapped
        }

        fun isLocalConfig(): Boolean {
            return localConfig
        }

        private fun setLocalConfig(localConfig: Boolean) {
            Companion.localConfig = localConfig
        }

        fun getOnlineMonitors(): MutableList<String?>? {
            return onlineMonitors
        }

        fun setOnlineMonitors(onlineMonitors: MutableList<String?>?) {
            synchronized(monitorSync) {
                if (isLocalConfig()) {
                    return
                }
                Companion.onlineMonitors = onlineMonitors
                setBootstrapped(true)
                setHosts(onlineMonitors.toTypedArray())
            }
        }
    }
}