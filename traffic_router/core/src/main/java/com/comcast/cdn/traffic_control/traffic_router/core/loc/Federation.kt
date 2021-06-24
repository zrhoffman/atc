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

import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress

class Federation(
    private val deliveryService: String?,
    private val federationMappings: MutableList<FederationMapping?>?
) : Comparable<Federation?> {
    fun getDeliveryService(): String? {
        return deliveryService
    }

    fun getFederationMappings(): MutableList<FederationMapping?>? {
        return federationMappings
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        val that = o as Federation?
        return if (if (deliveryService != null) deliveryService != that.deliveryService else that.deliveryService != null) false else !if (federationMappings != null) federationMappings != that.federationMappings else that.federationMappings != null
    }

    override fun hashCode(): Int {
        var result = deliveryService?.hashCode() ?: 0
        result = 31 * result + (federationMappings?.hashCode() ?: 0)
        return result
    }

    override fun compareTo(other: Federation?): Int {
        return deliveryService.compareTo(other.deliveryService)
    }

    fun containsCidrAddress(cidrAddress: CidrAddress?): Boolean {
        for (federationMapping in federationMappings) {
            if (federationMapping.containsCidrAddress(cidrAddress)) {
                return true
            }
        }
        return false
    }
}