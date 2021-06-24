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
package com.comcast.cdn.traffic_control.traffic_router.core.router

import com.comcast.cdn.traffic_control.traffic_router.core.ds.DeliveryService
import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord

class DNSRouteResult : RouteResult {
    private var addresses: MutableList<InetRecord?>? = null
    private var deliveryService: DeliveryService? = null
    override fun getResult(): Any? {
        return getAddresses()
    }

    fun getAddresses(): MutableList<InetRecord?>? {
        return addresses
    }

    fun setAddresses(addresses: MutableList<InetRecord?>?) {
        this.addresses = addresses
    }

    fun addAddresses(addresses: MutableList<InetRecord?>?) {
        if (this.addresses == null) {
            this.addresses = ArrayList()
        }
        this.addresses.addAll(addresses)
    }

    fun getDeliveryService(): DeliveryService? {
        return deliveryService
    }

    fun setDeliveryService(deliveryService: DeliveryService?) {
        this.deliveryService = deliveryService
    }
}