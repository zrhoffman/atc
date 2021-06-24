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

import com.fasterxml.jackson.annotation.JsonProperty

class Steering {
    @JsonProperty
    private var deliveryService: String? = null

    @JsonProperty
    private var clientSteering = false

    @JsonProperty
    private var targets: MutableList<SteeringTarget?>? = ArrayList()

    @JsonProperty
    private var filters: MutableList<SteeringFilter?>? = ArrayList()
    fun getTargets(): MutableList<SteeringTarget?>? {
        return targets
    }

    fun setTargets(targets: MutableList<SteeringTarget?>?) {
        this.targets = targets
    }

    fun getDeliveryService(): String? {
        return deliveryService
    }

    fun setDeliveryService(id: String?) {
        deliveryService = id
    }

    fun isClientSteering(): Boolean {
        return clientSteering
    }

    fun setClientSteering(clientSteering: Boolean) {
        this.clientSteering = clientSteering
    }

    fun getFilters(): MutableList<SteeringFilter?>? {
        return filters
    }

    fun setFilters(filters: MutableList<SteeringFilter?>?) {
        this.filters = filters
    }

    fun getBypassDestination(requestPath: String?): String? {
        for (filter in filters) {
            if (filter.matches(requestPath) && hasTarget(filter.getDeliveryService())) {
                return filter.getDeliveryService()
            }
        }
        return null
    }

    fun hasTarget(deliveryService: String?): Boolean {
        for (target in targets) {
            if (deliveryService == target.getDeliveryService()) {
                return true
            }
        }
        return false
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }
        if (o == null || javaClass != o.javaClass) {
            return false
        }
        val steering = o as Steering?
        return (deliveryService == steering.deliveryService
                && targets == steering.targets
                && filters == steering.filters)
    }

    override fun hashCode(): Int {
        var result = if (deliveryService != null) deliveryService.hashCode() else 0
        result = 31 * result + if (targets != null) targets.hashCode() else 0
        result = 31 * result + if (filters != null) filters.hashCode() else 0
        return result
    }
}