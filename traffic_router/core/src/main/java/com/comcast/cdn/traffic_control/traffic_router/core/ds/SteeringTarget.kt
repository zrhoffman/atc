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

import com.comcast.cdn.traffic_control.traffic_router.core.hash.DefaultHashable
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import com.fasterxml.jackson.annotation.JsonProperty

class SteeringTarget : DefaultHashable() {
    @JsonProperty
    private var deliveryService: String? = null

    @JsonProperty
    private var weight = 0

    @JsonProperty
    private var order = 0

    @JsonProperty
    private var geoOrder = 0

    @JsonProperty
    private var latitude = DEFAULT_LAT

    @JsonProperty
    private var longitude = DEFAULT_LON
    private var geolocation: Geolocation? = null
    fun generateHashes(): DefaultHashable? {
        return generateHashes(deliveryService, weight)
    }

    fun setDeliveryService(deliveryService: String?) {
        this.deliveryService = deliveryService
    }

    fun getDeliveryService(): String? {
        return deliveryService
    }

    fun setWeight(weight: Int) {
        this.weight = weight
    }

    fun getWeight(): Int {
        return weight
    }

    override fun setOrder(order: Int) {
        this.order = order
    }

    override fun getOrder(): Int {
        return order
    }

    fun setGeoOrder(geoOrder: Int) {
        this.geoOrder = geoOrder
    }

    fun getGeoOrder(): Int {
        return geoOrder
    }

    fun setLatitude(latitude: Double) {
        this.latitude = latitude
    }

    fun getLatitude(): Double {
        return latitude
    }

    fun setLongitude(longitude: Double) {
        this.longitude = longitude
    }

    fun getLongitude(): Double {
        return longitude
    }

    fun getGeolocation(): Geolocation? {
        if (geolocation != null) {
            return geolocation
        }
        if (latitude != DEFAULT_LAT && longitude != DEFAULT_LON) {
            geolocation = Geolocation(latitude, longitude)
        }
        return geolocation
    }

    fun setGeolocation(geolocation: Geolocation?) {
        this.geolocation = geolocation
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val target = o as SteeringTarget?
        if (weight != target.weight) return false
        if (order != target.order) return false
        if (geoOrder != target.geoOrder) return false
        if (latitude != target.latitude) return false
        if (longitude != target.longitude) return false
        return if (deliveryService != null) deliveryService == target.deliveryService else target.deliveryService == null
    }

    override fun hashCode(): Int {
        var result = if (deliveryService != null) deliveryService.hashCode() else 0
        result = 31 * result + weight
        result = 31 * result + order
        result = 31 * result + geoOrder
        result = 31 * result + latitude as Int
        result = 31 * result + longitude as Int
        return result
    }

    companion object {
        private const val DEFAULT_LAT = 0.0
        private const val DEFAULT_LON = 0.0
    }
}