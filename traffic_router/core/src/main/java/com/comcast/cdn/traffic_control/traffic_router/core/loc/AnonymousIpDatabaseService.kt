/*
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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseService
import com.maxmind.geoip2.DatabaseReader
import com.maxmind.geoip2.exception.GeoIp2Exception
import com.maxmind.geoip2.model.AnonymousIpResponse
import org.apache.log4j.Logger
import java.io.File
import java.io.IOException
import java.net.InetAddress

class AnonymousIpDatabaseService {
    private var initialized = false
    private var databaseFile: File? = null
    private var databaseReader: DatabaseReader? = null

    /*
	 * Reloads the anonymous ip database
	 */
    @Throws(IOException::class)
    fun reloadDatabase() {
        if (databaseReader != null) {
            databaseReader.close()
        }
        if (databaseFile != null) {
            val reader = createDatabaseReader(databaseFile)
            if (reader != null) {
                databaseReader = reader
                initialized = true
            } else {
                throw IOException("Could not create database reader")
            }
        }
    }

    fun setDatabaseFile(databaseFile: File?) {
        this.databaseFile = databaseFile
    }

    /*
	 * Verifies the database by attempting to recreate it
	 */
    @Throws(IOException::class)
    fun verifyDatabase(databaseFile: File?): Boolean {
        return createDatabaseReader(databaseFile) != null
    }

    /*
	 * Creates a DatabaseReader object using an input database file
	 */
    @Throws(IOException::class)
    private fun createDatabaseReader(databaseFile: File?): DatabaseReader? {
        if (!databaseFile.exists()) {
            AnonymousIpDatabaseService.Companion.LOGGER.warn(databaseFile.getAbsolutePath() + " does not exist yet!")
            return null
        }
        if (databaseFile.isDirectory()) {
            AnonymousIpDatabaseService.Companion.LOGGER.error(databaseFile.toString() + " is a directory, need a file")
            return null
        }
        AnonymousIpDatabaseService.Companion.LOGGER.info("Loading Anonymous IP db: " + databaseFile.getAbsolutePath())
        return try {
            DatabaseReader.Builder(databaseFile).build()
        } catch (e: Exception) {
            AnonymousIpDatabaseService.Companion.LOGGER.error(
                databaseFile.getAbsolutePath() + " is not a valid Anonymous IP data file",
                e
            )
            null
        }
    }

    /*
	 * Returns an AnonymousIpResponse from looking an ip up in the database
	 */
    fun lookupIp(ipAddress: InetAddress?): AnonymousIpResponse? {
        return if (initialized) {
            // Return an anonymousIp object after looking up the ip in the
            // database
            try {
                databaseReader.anonymousIp(ipAddress)
            } catch (e: GeoIp2Exception) {
                AnonymousIpDatabaseService.Companion.LOGGER.debug(
                    String.format(
                        "AnonymousIP: IP %s not found in anonymous ip database",
                        ipAddress.getHostAddress()
                    )
                )
                null
            } catch (e: IOException) {
                AnonymousIpDatabaseService.Companion.LOGGER.error(
                    "AnonymousIp ERR: IO Error during lookup of ip in anonymous ip database",
                    e
                )
                null
            }
        } else {
            null
        }
    }

    fun isInitialized(): Boolean {
        return initialized
    }

    /*
	 * Closes the database when the object is destroyed
	 */
    @Throws(Throwable::class)
    fun finalize() {
        if (databaseReader != null) {
            try {
                databaseReader.close()
                databaseReader = null
            } catch (e: IOException) {
                AnonymousIpDatabaseService.Companion.LOGGER.warn(
                    "Caught exception while trying to close anonymous ip database reader: ",
                    e
                )
            }
        }
        super.finalize()
    }

    companion object {
        private val LOGGER = Logger.getLogger(AnonymousIpDatabaseService::class.java)
    }
}