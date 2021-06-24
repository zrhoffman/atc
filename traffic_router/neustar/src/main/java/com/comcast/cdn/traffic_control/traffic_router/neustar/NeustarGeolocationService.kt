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
package com.comcast.cdn.traffic_control.traffic_router.neustar

import com.comcast.cdn.traffic_control.traffic_router.neustar.data.NeustarDatabaseUpdater

@Component
class NeustarGeolocationService : GeolocationService {
    private var databaseReader: GPDatabaseReader? = null

    @Autowired
    private val neustarDatabaseDirectory: File? = null

    @Override
    @Throws(GeolocationException::class)
    fun location(ip: String?): Geolocation? {
        return if (databaseReader == null) {
            null
        } else try {
            val geoPointResponse: GeoPointResponse = databaseReader.ipInfo(InetAddress.getByName(ip.split("/").get(0)))
            createGeolocation(geoPointResponse)
        } catch (e: AddressNotFoundException) {
            null
        } catch (e: Exception) {
            throw GeolocationException("Caught exception while attempting to determine location: " + e.getMessage(), e)
        }
    }

    @Override
    @Throws(IOException::class)
    fun verifyDatabase(databaseDirectory: File?): Boolean {
        throw RuntimeException(
            "verifyDatabase is no longer allowed, " + NeustarDatabaseUpdater::class.java.getSimpleName()
                .toString() + " is used for verification instead"
        )
    }

    @Override
    @Throws(IOException::class)
    fun reloadDatabase() {
        val gpDatabaseReader: GPDatabaseReader? = createDatabaseReader(neustarDatabaseDirectory)
        if (databaseReader != null) {
            databaseReader.close()
        }
        databaseReader = gpDatabaseReader
    }

    private fun createDatabaseReader(databaseDirectory: File?): GPDatabaseReader? {
        LOGGER.info("Loading Neustar db: $databaseDirectory")
        val t1: Long = System.currentTimeMillis()
        try {
            val gpDatabaseReader: GPDatabaseReader = Builder(databaseDirectory).build()
            LOGGER.info((System.currentTimeMillis() - t1).toString() + " msec to load Neustar db: " + databaseDirectory)
            return gpDatabaseReader
        } catch (e: Exception) {
            val path = if (databaseDirectory != null) databaseDirectory.getAbsolutePath() else "NULL"
            LOGGER.error("Database Directory " + path + " is not a valid Neustar database. " + e.getMessage())
        }
        return null
    }

    // Used by traffic router application context
    fun init() {}

    // Used by traffic router application context
    fun destroy() {
        if (databaseReader == null) {
            return
        }
        try {
            databaseReader.close()
            databaseReader = null
        } catch (ex: IOException) {
            LOGGER.warn("Caught exception while trying to close geolocation database reader: " + ex.getMessage(), ex)
        }
    }

    @Override
    fun isInitialized(): Boolean {
        return databaseReader != null
    }

    @Override
    fun setDatabaseFile(file: File?) {
        // Do nothing, this is just here for the interface.
        // The Maxmind version needs it due to how the GeolocationDatabaseUpdater class sets this up.
        // Once TR is running though this isn't going to change.
        // So instead we're just autowiring in the same file for both this and NeustarDatabaseUpdater
    }

    private fun createGeolocation(response: GeoPointResponse?): Geolocation? {
        val geolocation = Geolocation(response.getLatitude(), response.getLongitude())
        geolocation.setCity(response.getCity())
        geolocation.setCountryCode(response.getCountryCode())
        geolocation.setCountryName(response.getCountry())
        geolocation.setPostalCode(response.getPostalCode())
        return geolocation
    }

    companion object {
        private val LOGGER: Logger? = Logger.getLogger(NeustarGeolocationService::class.java)
    }
}