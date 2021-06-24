/*
 * Copyright 2015 Comcast Cable Communications Management, LLC
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
package com.comcast.cdn.traffic_control.traffic_router.core.edge

import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

/**
 * A physical location that has caches.
 */
class TrafficRouterLocation(id: String?, geolocation: Geolocation?) : Location(id, geolocation) {
    private val trafficRouters: MutableMap<String?, Node?>?

    /**
     * Adds the specified cache to this location.
     *
     * @param name
     * the name of the Traffic Router to add
     * @param trafficRouter
     * the Node representing a Traffic Router
     */
    fun addTrafficRouter(name: String?, trafficRouter: Node?) {
        trafficRouters[name] = trafficRouter
    }

    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is TrafficRouterLocation) {
            val rhs = obj as TrafficRouterLocation?
            EqualsBuilder()
                .append(id, rhs.getId())
                .isEquals
        } else {
            false
        }
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(id)
            .toHashCode()
    }

    /**
     * Retrieves the [Set] of Traffic Routers at this location.
     *
     * @return the caches
     */
    fun getTrafficRouters(): MutableList<Node?>? {
        return ArrayList(trafficRouters.values)
    }

    /**
     * Creates a TrafficRouteRLocation with the specified ID at the specified location.
     *
     * @param id
     * the id of the location
     * @param geolocation
     * the coordinates of this location
     */
    init {
        trafficRouters = HashMap()
    }
}