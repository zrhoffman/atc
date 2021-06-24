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
package com.comcast.cdn.traffic_control.traffic_router.geolocation

import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.sin
import kotlin.math.sqrt
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

class Geolocation
/**
 * Creates an immutable [Geolocation].
 *
 * @param latitude
 * in decimal degrees
 * @param longitude
 * in decimal degrees
 */(private val latitude: Double, private val longitude: Double) {
    private var postalCode: String? = null
    private var city: String? = null
    private var countryCode: String? = null
    private var countryName: String? = null
    private var defaultLocation = false
    fun getProperties(): MutableMap<String?, String?> {
        val map: MutableMap<String?, String?> = HashMap()
        map["latitude"] = latitude.toString()
        map["longitude"] = longitude.toString()
        map["postalCode"] = postalCode
        map["city"] = city
        map["countryCode"] = countryCode
        map["countryName"] = countryName
        return map
    }

    /**
     * Returns the great circle distance in kilometers between this [Geolocation] and the
     * specified location
     *
     * @param other
     * @return the great circle distance in km
     */
    fun getDistanceFrom(other: Geolocation?): Double {
        return if (other != null) {
            val dLat = Math.toRadians(getLatitude() - other.latitude)
            val dLon = Math.toRadians(getLongitude() - other.longitude)
            val a = (sin(dLat / 2) * sin(dLat / 2)
                    + (cos(Math.toRadians(getLatitude())) * cos(Math.toRadians(other.latitude))
                    * sin(dLon / 2) * sin(dLon / 2)))
            val c = 2 * atan2(sqrt(a), sqrt(1 - a))
            MEAN_EARTH_RADIUS * c
        } else {
            Double.POSITIVE_INFINITY
        }
    }

    override fun equals(other: Any?): Boolean {
        return when {
            this === other -> {
                true
            }
            other === null -> {
                false
            }
            other is Geolocation -> {
                EqualsBuilder()
                    .append(getLatitude(), other.getLatitude())
                    .append(getLongitude(), other.getLongitude())
                    .isEquals
            }
            else -> {
                false
            }
        }
    }

    /**
     * Retrieves the latitude in decimal degrees
     *
     * @return latitude in decimal degrees
     */
    fun getLatitude(): Double {
        return latitude
    }

    /**
     * Retrieves the longitude in decimal degrees
     *
     * @return longitude in decimal degrees
     */
    fun getLongitude(): Double {
        return longitude
    }

    fun getPostalCode(): String? {
        return postalCode
    }

    fun setPostalCode(postalCode: String?) {
        this.postalCode = postalCode
    }

    fun getCity(): String? {
        return city
    }

    fun setCity(city: String?) {
        this.city = city
    }

    fun getCountryCode(): String? {
        return countryCode
    }

    fun setCountryCode(countryCode: String?) {
        this.countryCode = countryCode
    }

    fun getCountryName(): String? {
        return countryName
    }

    fun setCountryName(countryName: String?) {
        this.countryName = countryName
    }

    fun isDefaultLocation(): Boolean {
        return defaultLocation
    }

    fun setDefaultLocation(defaultLocation: Boolean) {
        this.defaultLocation = defaultLocation
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(getLatitude())
            .append(getLongitude())
            .toHashCode()
    }

    override fun toString(): String {
        return "Geolocation [latitude=$latitude, longitude=$longitude]"
    }

    companion object {
        private const val MEAN_EARTH_RADIUS = 6371.0
    }
}