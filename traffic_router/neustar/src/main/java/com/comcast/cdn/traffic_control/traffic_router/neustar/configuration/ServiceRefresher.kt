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
package com.comcast.cdn.traffic_control.traffic_router.neustar.configuration

import com.comcast.cdn.traffic_control.traffic_router.neustar.NeustarGeolocationService

class ServiceRefresher : Runnable {
    private val logger: Logger? = Logger.getLogger(ServiceRefresher::class.java)

    @Autowired
    var neustarDatabaseUpdater: NeustarDatabaseUpdater? = null

    @Autowired
    var neustarGeolocationService: NeustarGeolocationService? = null
    @Override
    fun run() {
        try {
            if (neustarDatabaseUpdater.update() || !neustarGeolocationService.isInitialized()) {
                neustarGeolocationService.reloadDatabase()
            }
        } catch (e: Exception) {
            logger.error("Failed to refresh Neustar Geolocation Service:" + e.getMessage())
        }
    }
}