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

import com.comcast.cdn.traffic_control.traffic_router.core.config.WatcherConfig
import com.comcast.cdn.traffic_control.traffic_router.core.loc.AbstractServiceUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.io.IOException
import java.net.URL

abstract class AbstractResourceWatcher : AbstractServiceUpdater() {
    private var authorizationUrl: URL? = null
    private var postData: String? = null
    private var fetcher: ProtectedFetcher? = null
    var trafficOpsUtils: TrafficOpsUtils? = null
    private var timeout = 15000
    fun configure(config: JsonNode?) {
        var authUrl: URL?
        var credentials: String?
        try {
            authUrl = URL(trafficOpsUtils.getAuthUrl())
            credentials = trafficOpsUtils.getAuthJSON().toString()
        } catch (e: Exception) {
            LOGGER.warn(
                "Failed to update URL for TrafficOps authorization, " +
                        "check the api.auth.url, and the TrafficOps username and password configuration setting: " + e.message
            )
            // All or nothing, don't allow the watcher to be halfway misconfigured
            authUrl = authorizationUrl
            credentials = postData
        }
        if (authUrl == null || credentials == null) {
            LOGGER.warn("[ " + javaClass.simpleName + " ] Invalid Traffic Ops authorization URL or credentials data, not updating configuration!")
            return
        }
        val watcherConfig = WatcherConfig(getWatcherConfigPrefix(), config, trafficOpsUtils)
        val resourceUrl =
            if (watcherConfig.url != null && !watcherConfig.url.isEmpty()) watcherConfig.url else defaultDatabaseURL
        val pollingInterval = if (watcherConfig.interval > 0) watcherConfig.interval else pollingInterval
        val configTimeout = if (watcherConfig.timeout > 0) watcherConfig.timeout else timeout
        if (authUrl == authorizationUrl && credentials == postData && resourceUrl == dataBaseURL && pollingInterval == getPollingInterval() && configTimeout == timeout) {
            LOGGER.info("[ " + javaClass.name + " ] Nothing changed in configuration")
            return
        }

        // avoid recreating the fetcher if possible
        if (authUrl != authorizationUrl || credentials != postData || configTimeout != timeout) {
            authorizationUrl = authUrl
            postData = credentials
            timeout = configTimeout
            fetcher = ProtectedFetcher(authUrl.toString(), credentials, configTimeout)
        }
        setDataBaseURL(resourceUrl, pollingInterval)
    }

    protected open fun useData(data: String?): Boolean {
        return true
    }

    protected abstract fun verifyData(data: String?): Boolean

    @Throws(IOException::class)
    override fun loadDatabase(): Boolean {
        val existingDB = databasesDirectory.resolve(databaseName).toFile()
        if (!existingDB.exists() || !existingDB.canRead()) {
            return false
        }
        val jsonData = CharArray(existingDB.length() as Int)
        val reader = FileReader(existingDB)
        try {
            reader.read(jsonData)
        } finally {
            reader.close()
        }
        return useData(String(jsonData))
    }

    @Throws(IOException::class)
    override fun verifyDatabase(dbFile: File?): Boolean {
        if (!dbFile.exists() || !dbFile.canRead()) {
            return false
        }
        val jsonData = CharArray(dbFile.length() as Int)
        val reader = FileReader(dbFile)
        try {
            reader.read(jsonData)
        } finally {
            reader.close()
        }
        return verifyData(String(jsonData))
    }

    override fun downloadDatabase(url: String?, existingDb: File?): File? {
        if (trafficOpsUtils.getHostname() == null || trafficOpsUtils.getCdnName() == null) {
            return null
        }
        val interpolatedUrl = trafficOpsUtils.replaceTokens(url)
        if (fetcher == null) {
            LOGGER.warn("[" + javaClass.simpleName + "] Waiting for configuration to be processed, unable to download from '" + interpolatedUrl + "'")
            return null
        }
        var jsonData: String? = null
        try {
            jsonData = fetcher.fetchIfModifiedSince(interpolatedUrl, existingDb.lastModified())
        } catch (e: IOException) {
            LOGGER.warn("[ " + javaClass.simpleName + " ] Failed to fetch data from '" + interpolatedUrl + "': " + e.message)
        }
        if (jsonData == null) {
            return existingDb
        }
        var databaseFile: File? = null
        val fw: FileWriter
        try {
            databaseFile = File.createTempFile(tmpPrefix, tmpSuffix)
            fw = FileWriter(databaseFile)
            fw.write(jsonData)
            fw.flush()
            fw.close()
        } catch (e: IOException) {
            LOGGER.warn("Failed to create file from data received from '$interpolatedUrl'")
        }
        return databaseFile
    }

    fun setTrafficOpsUtils(trafficOpsUtils: TrafficOpsUtils?) {
        this.trafficOpsUtils = trafficOpsUtils
    }

    abstract fun getWatcherConfigPrefix(): String?

    companion object {
        private val LOGGER = Logger.getLogger(AbstractResourceWatcher::class.java)
    }
}