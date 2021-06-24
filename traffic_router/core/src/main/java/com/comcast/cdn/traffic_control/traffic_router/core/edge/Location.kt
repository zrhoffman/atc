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
open class Location
/**
 * Creates a Location with the specified ID at the specified location.
 *
 * @param id
 * the id of the location
 * @param geolocation
 * the coordinates of this location
 */(private val id: String?, private val geolocation: Geolocation?) {
    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is Location) {
            val rhs = obj as Location?
            EqualsBuilder()
                .append(getId(), rhs.getId())
                .isEquals
        } else {
            false
        }
    }

    /**
     * Gets geolocation.
     *
     * @return the geolocation
     */
    fun getGeolocation(): Geolocation? {
        return geolocation
    }

    /**
     * Gets id.
     *
     * @return the id
     */
    fun getId(): String? {
        return id
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(getId())
            .toHashCode()
    }

    fun getProperties(): MutableMap<String?, String?>? {
        val map = geolocation.getProperties()
        map["id"] = id
        return map
    }
}