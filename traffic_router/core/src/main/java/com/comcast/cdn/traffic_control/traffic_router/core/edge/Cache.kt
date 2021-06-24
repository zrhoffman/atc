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

import com.comcast.cdn.traffic_control.traffic_router.core.config.ParseException
import com.comcast.cdn.traffic_control.traffic_router.geolocation.Geolocation
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

class Cache @JvmOverloads constructor(
    id: String?,
    hashId: String?,
    hashCount: Int,
    private val geolocation: Geolocation? = null
) : Node(id, hashId, hashCount) {
    private val deliveryServices: MutableMap<String?, DeliveryServiceReference?>? = HashMap()
    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is Cache) {
            val rhs = obj as Cache?
            EqualsBuilder()
                .append(getId(), rhs.getId())
                .isEquals
        } else {
            false
        }
    }

    fun getDeliveryServices(): MutableCollection<DeliveryServiceReference?>? {
        return deliveryServices.values
    }

    fun getGeolocation(): Geolocation? {
        return geolocation
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(getId())
            .toHashCode()
    }

    override fun setDeliveryServices(deliveryServices: MutableCollection<DeliveryServiceReference?>?) {
        for (deliveryServiceReference in deliveryServices) {
            this.deliveryServices[deliveryServiceReference.getDeliveryServiceId()] = deliveryServiceReference
        }
    }

    override fun hasDeliveryService(deliveryServiceId: String?): Boolean {
        return deliveryServices.containsKey(deliveryServiceId)
    }

    override fun toString(): String {
        return "Cache [id=$id] "
    }

    /**
     * Contains a reference to a DeliveryService ID and the FQDN that should be used if this Cache
     * is used when supporting the DeliveryService.
     */
    class DeliveryServiceReference(deliveryServiceId: String?, fqdn: String?) {
        private val deliveryServiceId: String?
        private val fqdn: String?
        fun getDeliveryServiceId(): String? {
            return deliveryServiceId
        }

        fun getFqdn(): String? {
            return fqdn
        }

        init {
            if (fqdn.split("\\.".toRegex(), 2).toTypedArray().size != 2) {
                throw ParseException("Invalid FQDN ($fqdn) on delivery service $deliveryServiceId; please verify the HOST regex(es) in Traffic Ops")
            }
            this.deliveryServiceId = deliveryServiceId
            this.fqdn = fqdn
        }
    }
}