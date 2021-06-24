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

import com.comcast.cdn.traffic_control.traffic_router.core.edge.InetRecord
import com.comcast.cdn.traffic_control.traffic_router.core.util.CidrAddress

class FederationRegistry {
    private var federations: MutableList<Federation?>? = ArrayList()
    fun setFederations(federations: MutableList<Federation?>?) {
        synchronized(this.federations) { this.federations = federations }
    }

    fun findInetRecords(deliveryServiceId: String?, cidrAddress: CidrAddress?): MutableList<InetRecord?>? {
        var targetFederation: Federation? = null
        synchronized(federations) {
            for (federation in federations) {
                if (deliveryServiceId == federation.getDeliveryService()) {
                    targetFederation = federation
                    break
                }
            }
        }
        if (targetFederation == null) {
            return null
        }
        for (federationMapping in targetFederation.getFederationMappings()) {
            val cidrAddresses = federationMapping.getResolveAddresses(cidrAddress) ?: continue
            for (resolverAddress in cidrAddresses) {
                if (resolverAddress == cidrAddress || resolverAddress.includesAddress(cidrAddress)) {
                    return createInetRecords(federationMapping)
                }
            }
        }
        return null
    }

    protected fun createInetRecords(federationMapping: FederationMapping?): MutableList<InetRecord?>? {
        val inetRecord = InetRecord(federationMapping.getCname(), federationMapping.getTtl())
        val inetRecords: MutableList<InetRecord?> = ArrayList()
        inetRecords.add(inetRecord)
        return inetRecords
    }

    fun findFederations(cidrAddress: CidrAddress?): MutableList<Federation?>? {
        val results: MutableList<Federation?> = ArrayList()
        for (federation in federations) {
            if (federation.containsCidrAddress(cidrAddress)) {
                results.add(federation)
            }
        }
        return results
    }
}