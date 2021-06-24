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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpDatabaseUpdater
import org.apache.log4j.Logger
import java.io.File
import java.io.IOException

class AnonymousIpDatabaseUpdater : AbstractServiceUpdater() {
    private var anonymousIpDatabaseService: AnonymousIpDatabaseService? = null

    @Throws(IOException::class)
    /*
	 * Verifies the anonymous ip database
	 */  override fun verifyDatabase(dbFile: File?): Boolean {
        AnonymousIpDatabaseUpdater.Companion.LOGGER.debug("Verifying Anonymous IP Database")
        return anonymousIpDatabaseService.verifyDatabase(dbFile)
    }

    /*
	 * Sets the anonymous ip database file and reloads the database
	 */
    @Throws(IOException::class)
    override fun loadDatabase(): Boolean {
        AnonymousIpDatabaseUpdater.Companion.LOGGER.debug("Loading Anonymous IP Database")
        anonymousIpDatabaseService.setDatabaseFile(databasesDirectory.resolve(databaseName).toFile())
        anonymousIpDatabaseService.reloadDatabase()
        return true
    }

    /*
	 * Returns a boolean with the initialization state of the database
	 */  override fun isLoaded(): Boolean {
        return if (anonymousIpDatabaseService != null) {
            anonymousIpDatabaseService.isInitialized()
        } else loaded
    }

    fun setAnonymousIpDatabaseService(anonymousIpDatabaseService: AnonymousIpDatabaseService?) {
        this.anonymousIpDatabaseService = anonymousIpDatabaseService
    }

    companion object {
        private val LOGGER = Logger.getLogger(AnonymousIpDatabaseUpdater::class.java)
    }
}