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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationsWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import org.apache.log4j.Logger

class FederationsWatcher : AbstractResourceWatcher() {
    private var federationRegistry: FederationRegistry? = null
    public override fun useData(data: String?): Boolean {
        try {
            federationRegistry.setFederations(FederationsBuilder().fromJSON(data))
            return true
        } catch (e: Exception) {
            FederationsWatcher.Companion.LOGGER.warn("Failed updating federations data from $dataBaseURL")
        }
        return false
    }

    override fun verifyData(data: String?): Boolean {
        try {
            FederationsBuilder().fromJSON(data)
            return true
        } catch (e: Exception) {
            FederationsWatcher.Companion.LOGGER.warn("Failed to build federations data from $dataBaseURL")
        }
        return false
    }

    fun setFederationRegistry(federationRegistry: FederationRegistry?) {
        this.federationRegistry = federationRegistry
    }

    override fun getWatcherConfigPrefix(): String? {
        return "federationmapping"
    }

    companion object {
        private val LOGGER = Logger.getLogger(FederationsWatcher::class.java)
        val DEFAULT_FEDERATION_DATA_URL: String? = "https://\${toHostname}/api/2.0/federations/all"
    }

    init {
        setDatabaseUrl(FederationsWatcher.Companion.DEFAULT_FEDERATION_DATA_URL)
        setDefaultDatabaseUrl(FederationsWatcher.Companion.DEFAULT_FEDERATION_DATA_URL)
    }
}