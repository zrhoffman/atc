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

import java.io.File
import java.io.IOException

class GeolocationDatabaseUpdater : AbstractServiceUpdater() {
    private var maxmindGeolocationService: MaxmindGeolocationService? = null

    @Throws(IOException::class)
    override fun verifyDatabase(dbFile: File?): Boolean {
        return maxmindGeolocationService.verifyDatabase(dbFile)
    }

    @Throws(IOException::class)
    override fun loadDatabase(): Boolean {
        maxmindGeolocationService.setDatabaseFile(databasesDirectory.resolve(databaseName).toFile())
        maxmindGeolocationService.reloadDatabase()
        return true
    }

    override fun isLoaded(): Boolean {
        return if (maxmindGeolocationService != null) {
            maxmindGeolocationService.isInitialized()
        } else loaded
    }

    fun setMaxmindGeolocationService(maxmindGeolocationService: MaxmindGeolocationService?) {
        this.maxmindGeolocationService = maxmindGeolocationService
    }
}