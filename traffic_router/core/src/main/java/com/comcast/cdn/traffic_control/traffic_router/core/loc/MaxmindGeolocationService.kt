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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.MaxmindGeolocationService
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationException
import com.comcast.cdn.traffic_control.traffic_router.geolocation.GeolocationService
import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.exception.AddressNotFoundException
import com.maxmind.geoip2.model.CityResponse
import org.apache.log4j.Logger
import java.io.File
import java.io.IOException
import java.net.InetAddress

class MaxmindGeolocationService : GeolocationService {
    private var initialized = false
    private var databaseReader: DatabaseReader? = null
    private var databaseFile: File? = null

    @Throws(GeolocationException::class)
    private fun getCityResponse(databaseReader: DatabaseReader?, address: String?): CityResponse? {
        return try {
            databaseReader.city(InetAddress.getByName(address))
        } catch (e: AddressNotFoundException) {
            null
        } catch (e: Exception) {
            throw GeolocationException("Caught exception while attempting to determine location: " + e.message, e)
        }
    }

    @Throws(GeolocationException::class)
    override fun location(ip: String?): Geolocation? {
        if (databaseReader == null) {
            return null
        }
        val response = getCityResponse(databaseReader, ip.split("/".toRegex()).toTypedArray()[0])
        return if (isResponseValid(response)) createGeolocation(response) else null
    }

    private fun isResponseValid(response: CityResponse?): Boolean {
        return response != null && response.location != null && response.location.latitude != null && response.location.longitude != null
    }

    @Throws(IOException::class)
    override fun reloadDatabase() {
        if (databaseReader != null) {
            databaseReader.close()
        }
        if (databaseFile != null) {
            val reader = createDatabaseReader(databaseFile)
            if (reader != null) {
                databaseReader = reader
                initialized = true
            }
        }
    }

    @Throws(IOException::class)
    override fun verifyDatabase(databaseFile: File?): Boolean {
        return createDatabaseReader(databaseFile) != null
    }

    override fun setDatabaseFile(databaseFile: File?) {
        this.databaseFile = databaseFile
    }

    @Throws(IOException::class)
    private fun createDatabaseReader(databaseFile: File?): DatabaseReader? {
        if (!databaseFile.exists()) {
            MaxmindGeolocationService.Companion.LOGGER.warn(databaseFile.getAbsolutePath() + " does not exist yet!")
            return null
        }
        if (databaseFile.isDirectory()) {
            MaxmindGeolocationService.Companion.LOGGER.error(databaseFile.toString() + " is a directory, need a file")
            return null
        }
        MaxmindGeolocationService.Companion.LOGGER.info("Loading MaxMind db: " + databaseFile.getAbsolutePath())
        return try {
            val reader = DatabaseReader.Builder(databaseFile).build()
            getCityResponse(reader, "127.0.0.1")
            reader
        } catch (e: Exception) {
            MaxmindGeolocationService.Companion.LOGGER.error(databaseFile.getAbsolutePath() + " is not a valid Maxmind data file.  " + e.message)
            null
        }
    }

    override fun isInitialized(): Boolean {
        return initialized
    }

    fun init() {}
    fun destroy() {
        if (databaseReader == null) {
            return
        }
        try {
            databaseReader.close()
            databaseReader = null
        } catch (ex: IOException) {
            MaxmindGeolocationService.Companion.LOGGER.warn(
                "Caught exception while trying to close geolocation database reader: " + ex.message,
                ex
            )
        }
    }

    fun createGeolocation(response: CityResponse?): Geolocation? {
        val latitude = response.getLocation().latitude
        val longitude = response.getLocation().longitude
        val geolocation = Geolocation(latitude, longitude)
        if (response.getPostal() != null) {
            geolocation.postalCode = response.getPostal().code
        }
        if (response.getCity() != null) {
            geolocation.city = response.getCity().name
        }
        if (response.getCountry() != null) {
            geolocation.countryCode = response.getCountry().isoCode
            geolocation.countryName = response.getCountry().name
        }
        if (geolocation.city == null && geolocation.postalCode == null && response.getSubdivisions().isEmpty()) {
            geolocation.isDefaultLocation = true
        }
        return geolocation
    }

    companion object {
        private val LOGGER = Logger.getLogger(MaxmindGeolocationService::class.java)
    }
}