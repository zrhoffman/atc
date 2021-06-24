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
package com.comcast.cdn.traffic_control.traffic_router.core.status.model

/**
 * Model for a CacheLocation.
 */
class LocationModel {
    private var locationID: String? = null
    private var description: String? = null
    private var latitude = 0.0
    private var longitude = 0.0
    var caches: MutableList<CacheModel?>? = null

    /**
     * Gets description.
     *
     * @return the description
     */
    fun getDescription(): String? {
        return description
    }

    /**
     * Gets latitude.
     *
     * @return the latitude
     */
    fun getLatitude(): Double {
        return latitude
    }

    /**
     * Gets locationID.
     *
     * @return the locationID
     */
    fun getLocationID(): String? {
        return locationID
    }

    /**
     * Gets longitude.
     *
     * @return the longitude
     */
    fun getLongitude(): Double {
        return longitude
    }

    /**
     * Sets description.
     *
     * @param description
     * the description to set
     */
    fun setDescription(description: String?) {
        this.description = description
    }

    /**
     * Sets latitude.
     *
     * @param latitude
     * the latitude to set
     */
    fun setLatitude(latitude: Double) {
        this.latitude = latitude
    }

    /**
     * Sets locationID.
     *
     * @param locationID
     * the locationID to set
     */
    fun setLocationID(locationID: String?) {
        this.locationID = locationID
    }

    /**
     * Sets longitude.
     *
     * @param longitude
     * the longitude to set
     */
    fun setLongitude(longitude: Double) {
        this.longitude = longitude
    }
}