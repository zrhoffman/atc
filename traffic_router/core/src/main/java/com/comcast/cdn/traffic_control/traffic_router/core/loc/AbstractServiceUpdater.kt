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
package com.comcast.cdn.traffic_control.traffic_router.core.loc

import com.comcast.cdn.traffic_control.traffic_router.core.loc.AbstractServiceUpdater
import com.comcast.cdn.traffic_control.traffic_router.core.router.TrafficRouterManager
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import org.apache.commons.codec.digest.DigestUtils
import org.apache.commons.io.IOUtils
import org.apache.log4j.Logger
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Arrays
import java.util.Date
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream

abstract class AbstractServiceUpdater {
    var dataBaseURL: String? = null
    protected var defaultDatabaseURL: String? = null
    protected var databaseName: String? = null
    protected var executorService: ScheduledExecutorService? = null
    private var pollingInterval: Long = 0
    protected var loaded = false
    protected var scheduledService: ScheduledFuture<*>? = null
    private var trafficRouterManager: TrafficRouterManager? = null
    protected var databasesDirectory: Path? = null
    private var eTag: String? = null
    fun destroy() {
        executorService.shutdownNow()
    }

    /**
     * Gets dataBaseURL.
     *
     * @return the dataBaseURL
     */
    fun getDataBaseURL(): String? {
        return dataBaseURL
    }

    /**
     * Gets pollingInterval.
     *
     * @return the pollingInterval
     */
    fun getPollingInterval(): Long {
        return if (pollingInterval == 0L) {
            10000
        } else pollingInterval
    }

    private val updater: Runnable? = object : Runnable {
        override fun run() {
            try {
                updateDatabase()
            } catch (t: Throwable) {
                // Catching Throwable prevents this Service Updater thread from silently dying
                AbstractServiceUpdater.Companion.LOGGER.error(
                    "[" + javaClass.simpleName + "] Failed updating database!",
                    t
                )
            }
        }
    }

    fun init() {
        val pollingInterval = getPollingInterval()
        val nextFetchDate = Date(System.currentTimeMillis() + pollingInterval)
        AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Fetching external resource " + dataBaseURL + " at interval: " + pollingInterval + " : " + TimeUnit.MILLISECONDS + " next update occurrs at " + nextFetchDate)
        scheduledService =
            executorService.scheduleWithFixedDelay(updater, pollingInterval, pollingInterval, TimeUnit.MILLISECONDS)
    }

    fun updateDatabase(): Boolean {
        try {
            if (!Files.exists(databasesDirectory)) {
                Files.createDirectories(databasesDirectory)
            }
        } catch (ex: IOException) {
            AbstractServiceUpdater.Companion.LOGGER.error(databasesDirectory.toString() + " does not exist and cannot be created!")
            return false
        }
        val existingDB = databasesDirectory.resolve(databaseName).toFile()
        if (!isLoaded()) {
            try {
                setLoaded(loadDatabase())
            } catch (e: Exception) {
                AbstractServiceUpdater.Companion.LOGGER.warn("[" + javaClass.simpleName + "] Failed to load existing database! " + e.message)
            }
        } else if (!needsUpdating(existingDB)) {
            AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Location database does not require updating.")
            return false
        }
        var newDB: File? = null
        var isModified = true
        val databaseURL = getDataBaseURL()
        if (databaseURL == null) {
            AbstractServiceUpdater.Companion.LOGGER.warn("[" + javaClass.simpleName + "] Skipping download/update: database URL is null")
            return false
        }
        try {
            try {
                newDB = downloadDatabase(databaseURL, existingDB)
                trafficRouterManager.trackEvent("last" + javaClass.simpleName + "Check")

                // if the remote db's timestamp is less than or equal to ours, the above returns existingDB
                if (newDB === existingDB) {
                    isModified = false
                }
            } catch (e: Exception) {
                AbstractServiceUpdater.Companion.LOGGER.fatal(
                    "[" + javaClass.simpleName + "] Caught exception while attempting to download: " + getDataBaseURL(),
                    e
                )
                return false
            }
            if (!isModified || newDB == null || !newDB.exists()) {
                return false
            }
            try {
                if (!verifyDatabase(newDB)) {
                    AbstractServiceUpdater.Companion.LOGGER.warn("[" + javaClass.simpleName + "] " + newDB.absolutePath + " from " + getDataBaseURL() + " is invalid!")
                    return false
                }
            } catch (e: Exception) {
                AbstractServiceUpdater.Companion.LOGGER.error("[" + javaClass.simpleName + "] Failed verifying database " + newDB.absolutePath + " : " + e.message)
                return false
            }
            try {
                if (copyDatabaseIfDifferent(existingDB, newDB)) {
                    setLoaded(loadDatabase())
                    trafficRouterManager.trackEvent("last" + javaClass.simpleName + "Update")
                } else {
                    newDB.delete()
                }
            } catch (e: Exception) {
                AbstractServiceUpdater.Companion.LOGGER.error("[" + javaClass.simpleName + "] Failed copying and loading new database " + newDB.absolutePath + " : " + e.message)
            }
        } finally {
            if (newDB != null && newDB !== existingDB && newDB.exists()) {
                AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Try to delete downloaded temp file")
                deleteDatabase(newDB)
            }
        }
        return true
    }

    @Throws(IOException::class, JsonUtilsException::class)
    abstract fun verifyDatabase(dbFile: File?): Boolean

    @Throws(IOException::class, JsonUtilsException::class)
    abstract fun loadDatabase(): Boolean
    fun setDatabaseName(databaseName: String?) {
        this.databaseName = databaseName
    }

    fun stopServiceUpdater() {
        if (scheduledService != null) {
            AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Stopping service updater")
            scheduledService.cancel(false)
        }
    }

    fun cancelServiceUpdater() {
        stopServiceUpdater()
        pollingInterval = 0
        dataBaseURL = null
    }

    fun setDataBaseURL(url: String?, refresh: Long) {
        if (refresh != 0L && refresh != pollingInterval) {
            pollingInterval = refresh
            AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Restarting schedule for " + url + " with interval: " + refresh)
            stopServiceUpdater()
            init()
        }
        if (url != null && url != dataBaseURL || refresh != 0L && refresh != pollingInterval) {
            dataBaseURL = url
            setLoaded(false)
            Thread(updater).start()
        }
    }

    fun setDatabaseUrl(url: String?) {
        dataBaseURL = url
    }

    fun setDefaultDatabaseUrl(url: String?) {
        defaultDatabaseURL = url
    }

    /**
     * Sets executorService.
     *
     * @param executorService
     * the executorService to set
     */
    fun setExecutorService(executorService: ScheduledExecutorService?) {
        this.executorService = executorService
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
    fun filesEqual(a: File?, b: File?): Boolean {
        if (!a.exists() && !b.exists()) {
            return true
        }
        if (!a.exists() || !b.exists()) {
            return false
        }
        return if (a.isDirectory() && b.isDirectory()) {
            compareDirectories(a, b)
        } else compareFiles(a, b)
    }

    @Throws(IOException::class)
    private fun compareDirectories(a: File?, b: File?): Boolean {
        val aFileList = a.listFiles()
        val bFileList = b.listFiles()
        if (aFileList.size != bFileList.size) {
            return false
        }
        Arrays.sort(aFileList)
        Arrays.sort(bFileList)
        for (i in aFileList.indices) {
            if (aFileList[i].length() != bFileList[i].length()) {
                return false
            }
        }
        return true
    }

    @Throws(IOException::class)
    private fun fileMd5(file: File?): String? {
        FileInputStream(file).use { stream -> return DigestUtils.md5Hex(stream) }
    }

    @Throws(IOException::class)
    private fun compareFiles(a: File?, b: File?): Boolean {
        return if (a.length() != b.length()) {
            false
        } else fileMd5(a) == fileMd5(b)
    }

    @Throws(IOException::class)
    protected fun copyDatabaseIfDifferent(existingDB: File?, newDB: File?): Boolean {
        if (filesEqual(existingDB, newDB)) {
            AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] database unchanged.")
            existingDB.setLastModified(newDB.lastModified())
            return false
        }
        if (existingDB.isDirectory() && newDB.isDirectory()) {
            moveDirectory(existingDB, newDB)
            AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Successfully updated database " + existingDB)
            return true
        }
        if (existingDB != null && existingDB.exists()) {
            deleteDatabase(existingDB)
        }
        newDB.setReadable(true, true)
        newDB.setWritable(true, false)
        val renamed = newDB.renameTo(existingDB)
        if (!renamed) {
            AbstractServiceUpdater.Companion.LOGGER.fatal(
                "[" + javaClass.simpleName + "] Unable to rename " + newDB + " to " + existingDB.getAbsolutePath() + "; current working directory is " + System.getProperty(
                    "user.dir"
                )
            )
            return false
        }
        AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Successfully updated database " + existingDB)
        return true
    }

    @Throws(IOException::class)
    private fun moveDirectory(existingDB: File?, newDB: File?) {
        AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Moving Location database from: " + newDB + ", to: " + existingDB)
        for (file in existingDB.listFiles()) {
            file.setReadable(true, true)
            file.setWritable(true, false)
            file.delete()
        }
        existingDB.delete()
        Files.move(newDB.toPath(), existingDB.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private fun deleteDatabase(db: File?) {
        db.setReadable(true, true)
        db.setWritable(true, false)
        if (db.isDirectory()) {
            for (file in db.listFiles()) {
                file.delete()
            }
            AbstractServiceUpdater.Companion.LOGGER.debug("[" + javaClass.simpleName + "] Successfully deleted database under: " + db)
        } else {
            db.delete()
        }
    }

    protected var sourceCompressed = true
    protected var tmpPrefix: String? = "loc"
    protected var tmpSuffix: String? = ".dat"

    @Throws(IOException::class)
    protected open fun downloadDatabase(url: String?, existingDb: File?): File? {
        AbstractServiceUpdater.Companion.LOGGER.info("[" + javaClass.simpleName + "] Downloading database: " + url)
        val dbURL = URL(url)
        val conn = dbURL.openConnection() as HttpURLConnection
        if (useModifiedTimestamp(existingDb)) {
            conn.ifModifiedSince = existingDb.lastModified()
            if (eTag != null) {
                conn.setRequestProperty("If-None-Match", eTag)
            }
        }
        var `in` = conn.inputStream
        eTag = conn.getHeaderField("ETag")
        if (conn.responseCode == HttpURLConnection.HTTP_NOT_MODIFIED) {
            AbstractServiceUpdater.Companion.LOGGER.info(
                "[" + javaClass.simpleName + "] " + url + " not modified since our existing database's last update time of " + Date(
                    existingDb.lastModified()
                )
            )
            return existingDb
        }
        if (sourceCompressed) {
            `in` = GZIPInputStream(`in`)
        }
        val outputFile = File.createTempFile(tmpPrefix, tmpSuffix)
        val out: OutputStream = FileOutputStream(outputFile)
        IOUtils.copy(`in`, out)
        IOUtils.closeQuietly(`in`)
        IOUtils.closeQuietly(out)
        return outputFile
    }

    private fun useModifiedTimestamp(existingDb: File?): Boolean {
        return existingDb != null && existingDb.exists() && existingDb.lastModified() > 0 && (!existingDb.isDirectory || existingDb.listFiles().size > 0)
    }

    protected fun needsUpdating(existingDB: File?): Boolean {
        val now = System.currentTimeMillis()
        val fileTime = existingDB.lastModified()
        val pollingIntervalInMS = getPollingInterval()
        return fileTime + pollingIntervalInMS < now
    }

    fun setLoaded(loaded: Boolean) {
        this.loaded = loaded
    }

    open fun isLoaded(): Boolean {
        return loaded
    }

    fun setTrafficRouterManager(trafficRouterManager: TrafficRouterManager?) {
        this.trafficRouterManager = trafficRouterManager
    }

    fun getDatabasesDirectory(): Path? {
        return databasesDirectory
    }

    fun setDatabasesDirectory(databasesDirectory: Path?) {
        this.databasesDirectory = databasesDirectory
    }

    companion object {
        private val LOGGER = Logger.getLogger(AbstractServiceUpdater::class.java)
    }
}