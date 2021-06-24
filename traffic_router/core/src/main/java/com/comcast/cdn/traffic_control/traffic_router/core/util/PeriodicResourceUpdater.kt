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

import com.comcast.cdn.traffic_control.traffic_router.core.util.PeriodicResourceUpdater
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import org.asynchttpclient.AsyncCompletionHandler
import org.asynchttpclient.AsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClient
import org.asynchttpclient.DefaultAsyncHttpClientConfig
import org.asynchttpclient.Request
import org.asynchttpclient.Response
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FileReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.StringReader
import java.net.URI
import java.net.URISyntaxException
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream

/**
 *
 * @author jlaue
 */
class PeriodicResourceUpdater(
    private val listener: AbstractUpdatable?,
    protected val urls: ResourceUrl?,
    protected var databaseLocation: String?,
    interval: Int,
    pauseTilLoaded: Boolean
) {
    private var asyncHttpClient: AsyncHttpClient? = null
    protected var executorService = Executors.newSingleThreadScheduledExecutor()
    protected var pollingInterval: Long
    protected var scheduledService: ScheduledFuture<*>? = null
    fun destroy() {
        executorService.shutdownNow()
        while (!asyncHttpClient.isClosed()) {
            try {
                asyncHttpClient.close()
            } catch (e: IOException) {
                PeriodicResourceUpdater.Companion.LOGGER.error(e.message)
            }
        }
    }

    /**
     * Gets pollingInterval.
     *
     * @return the pollingInterval
     */
    fun getPollingInterval(): Long {
        return if (pollingInterval == 0L) {
            66000
        } else pollingInterval
    }

    private val updater: Runnable? = Runnable { updateDatabase() }
    private var hasBeenLoaded = false
    private val pauseTilLoaded: Boolean
    fun init() {
        asyncHttpClient = newAsyncClient()
        putCurrent()
        PeriodicResourceUpdater.Companion.LOGGER.info("Starting schedule with interval: " + getPollingInterval() + " : " + TimeUnit.MILLISECONDS)
        scheduledService =
            executorService.scheduleWithFixedDelay(updater, 0, getPollingInterval(), TimeUnit.MILLISECONDS)
        // wait here until something is loaded
        val existingDB = File(databaseLocation)
        if (pauseTilLoaded) {
            while (!existingDB.exists()) {
                PeriodicResourceUpdater.Companion.LOGGER.info("Waiting for valid: $databaseLocation")
                try {
                    Thread.sleep(getPollingInterval())
                } catch (e: InterruptedException) {
                }
            }
        }
    }

    private fun newAsyncClient(): AsyncHttpClient? {
        return DefaultAsyncHttpClient(
            DefaultAsyncHttpClientConfig.Builder()
                .setFollowRedirect(true)
                .setConnectTimeout(10000)
                .build()
        )
    }

    @Synchronized
    private fun putCurrent() {
        val existingDB = File(databaseLocation)
        if (existingDB.exists()) {
            try {
                listener.update(IOUtils.toString(FileReader(existingDB)))
            } catch (e: Exception) {
                PeriodicResourceUpdater.Companion.LOGGER.warn(e, e)
            }
        }
    }

    @Synchronized
    fun updateDatabase(): Boolean {
        val existingDB = File(databaseLocation)
        try {
            if (!hasBeenLoaded || needsUpdating(existingDB)) {
                val request = getRequest(urls.nextUrl())
                if (request != null) {
                    request.headers.add("Accept-Encoding", PeriodicResourceUpdater.Companion.GZIP_ENCODING_STRING)
                    if (asyncHttpClient != null && !asyncHttpClient.isClosed()) {
                        asyncHttpClient.executeRequest<Any?>(
                            request,
                            PeriodicResourceUpdater.UpdateHandler(request)
                        ) // AsyncHandlers are NOT thread safe; one instance per request
                    }
                    return true
                }
            } else {
                PeriodicResourceUpdater.Companion.LOGGER.info("Database " + existingDB.absolutePath + " does not require updating.")
            }
        } catch (e: Exception) {
            PeriodicResourceUpdater.Companion.LOGGER.warn(e.message, e)
        }
        return false
    }

    fun updateDatabase(newDB: String?): Boolean {
        val existingDB = File(databaseLocation)
        try {
            if (newDB != null && !filesEqual(existingDB, newDB)) {
                listener.cancelUpdate()
                if (listener.update(newDB)) {
                    copyDatabase(existingDB, newDB)
                    PeriodicResourceUpdater.Companion.LOGGER.info("updated " + existingDB.absolutePath)
                    listener.setLastUpdated(System.currentTimeMillis())
                    listener.complete()
                } else {
                    PeriodicResourceUpdater.Companion.LOGGER.warn("File rejected: " + existingDB.absolutePath)
                }
            } else {
                listener.noChange()
            }
            hasBeenLoaded = true
            return true
        } catch (e: Exception) {
            PeriodicResourceUpdater.Companion.LOGGER.warn(e.message, e)
        }
        return false
    }

    fun setDatabaseLocation(databaseLocation: String?) {
        this.databaseLocation = databaseLocation
    }

    /**
     * Sets executorService.
     *
     * @param es
     * the executorService to set
     */
    fun setExecutorService(es: ScheduledExecutorService?) {
        executorService = es
    }

    /**
     * Sets pollingInterval.
     *
     * @param pollingInterval
     * the pollingInterval to set
     */
    fun setPollingInterval(pollingInterval: Long) {
        this.pollingInterval = pollingInterval
    }

    @Throws(IOException::class)
    private fun fileMd5(file: File?): String? {
        FileInputStream(file).use { stream -> return DigestUtils.md5Hex(stream) }
    }

    @Throws(IOException::class)
    fun filesEqual(a: File?, newDB: String?): Boolean {
        if (!a.exists()) {
            return newDB == null
        }
        if (newDB == null) {
            return false
        }
        if (a.length() != newDB.length.toLong()) {
            return false
        }
        IOUtils.toInputStream(newDB).use { newDBStream -> return fileMd5(a) == DigestUtils.md5Hex(newDBStream) }
    }

    @Synchronized
    @Throws(IOException::class)
    protected fun copyDatabase(existingDB: File?, newDB: String?) {
        StringReader(newDB).use { `in` ->
            FileOutputStream(existingDB).use { out ->
                out.channel.tryLock().use { lock ->
                    if (lock == null) {
                        PeriodicResourceUpdater.Companion.LOGGER.error("Database " + existingDB.getAbsolutePath() + " locked by another process.")
                        return
                    }
                    IOUtils.copy(`in`, out)
                    existingDB.setReadable(true, false)
                    existingDB.setWritable(true, true)
                    lock.release()
                }
            }
        }
    }

    protected fun needsUpdating(existingDB: File?): Boolean {
        val now = System.currentTimeMillis()
        val fileTime = existingDB.lastModified()
        val pollingIntervalInMS = getPollingInterval()
        return fileTime + pollingIntervalInMS < now
    }

    private inner class UpdateHandler(val request: Request?) : AsyncCompletionHandler<Any?>() {
        @Throws(IOException::class)
        override fun onCompleted(response: Response?): Int? {
            // Do something with the Response
            val code = response.getStatusCode()
            if (code != 200) {
                if (code >= 400) {
                    PeriodicResourceUpdater.Companion.LOGGER.warn("failed to GET " + response.getUri() + " - returned status code " + code)
                }
                return code
            }
            val responseBody: String?
            if (PeriodicResourceUpdater.Companion.GZIP_ENCODING_STRING == response.getHeader("Content-Encoding")) {
                val stringBuilder = StringBuilder()
                val zippedInputStream = GZIPInputStream(response.getResponseBodyAsStream())
                val r = BufferedReader(InputStreamReader(zippedInputStream))
                var line: String?
                while (r.readLine().also { line = it } != null) {
                    stringBuilder.append(line)
                }
                responseBody = stringBuilder.toString()
            } else {
                responseBody = response.getResponseBody()
            }
            updateDatabase(responseBody)
            return code
        }

        override fun onThrowable(t: Throwable?) {
            PeriodicResourceUpdater.Companion.LOGGER.warn("Failed request " + request.getUrl() + ": " + t, t)
        }
    }

    private fun getRequest(url: String?): Request? {
        return try {
            URI(url)
            asyncHttpClient.prepareGet(url).setFollowRedirect(true).build()
        } catch (e: URISyntaxException) {
            PeriodicResourceUpdater.Companion.LOGGER.fatal("Cannot update database from Bad URI - $url")
            null
        }
    }

    companion object {
        private val LOGGER = Logger.getLogger(PeriodicResourceUpdater::class.java)
        private val GZIP_ENCODING_STRING: String? = "gzip"
    }

    init {
        pollingInterval = interval.toLong()
        this.pauseTilLoaded = pauseTilLoaded
    }
}