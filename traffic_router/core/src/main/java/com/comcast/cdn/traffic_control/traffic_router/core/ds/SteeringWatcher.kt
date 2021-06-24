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
package com.comcast.cdn.traffic_control.traffic_router.core.ds

import com.comcast.cdn.traffic_control.traffic_router.core.ds.SteeringWatcher
import com.comcast.cdn.traffic_control.traffic_router.core.util.AbstractResourceWatcher
import org.apache.log4j.Logger

class SteeringWatcher : AbstractResourceWatcher() {
    private var steeringRegistry: SteeringRegistry? = null
    public override fun useData(data: String?): Boolean {
        try {
            // NOTE: it is likely that the steering data will contain xml_ids for delivery services
            // that haven't been added to the CRConfig yet. This is okay because the SteeringRegistry
            // will only be queried for Delivery Service xml_ids that exist in CRConfig
            steeringRegistry.update(data)
            return true
        } catch (e: Exception) {
            SteeringWatcher.Companion.LOGGER.warn("Failed updating steering registry with data from $dataBaseURL")
        }
        return false
    }

    override fun verifyData(data: String?): Boolean {
        try {
            return steeringRegistry.verify(data)
        } catch (e: Exception) {
            SteeringWatcher.Companion.LOGGER.warn("Failed to build steering data while verifying")
        }
        return false
    }

    override fun getWatcherConfigPrefix(): String? {
        return "steeringmapping"
    }

    fun setSteeringRegistry(steeringRegistry: SteeringRegistry?) {
        this.steeringRegistry = steeringRegistry
    }

    companion object {
        private val LOGGER = Logger.getLogger(SteeringWatcher::class.java)
        val DEFAULT_STEERING_DATA_URL: String? = "https://\${toHostname}/api/2.0/steering"
    }

    init {
        setDatabaseUrl(SteeringWatcher.Companion.DEFAULT_STEERING_DATA_URL)
        setDefaultDatabaseUrl(SteeringWatcher.Companion.DEFAULT_STEERING_DATA_URL)
    }
}