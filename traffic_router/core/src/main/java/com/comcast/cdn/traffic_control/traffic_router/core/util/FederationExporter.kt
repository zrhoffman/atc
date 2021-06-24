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
package com.comcast.cdn.traffic_control.traffic_router.core.util

import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationMapping
import com.comcast.cdn.traffic_control.traffic_router.core.loc.FederationRegistry

class FederationExporter {
    private var federationRegistry: FederationRegistry? = null
    fun getMatchingFederations(cidrAddress: CidrAddress?): MutableList<Any?>? {
        val federationsList: MutableList<Any?> = ArrayList()
        for (federation in federationRegistry.findFederations(cidrAddress)) {
            val filteredFederationMappings: MutableList<MutableMap<String?, Any?>?> = ArrayList()
            for (federationMapping in federation.federationMappings) {
                filteredFederationMappings.add(getMappingProperties(cidrAddress, federationMapping))
            }
            val federationProperties: MutableMap<String?, Any?> = HashMap()
            federationProperties["deliveryService"] = federation.deliveryService
            federationProperties["federationMappings"] = filteredFederationMappings
            federationsList.add(federationProperties)
        }
        return federationsList
    }

    private fun getMappingProperties(
        cidrAddress: CidrAddress?,
        federationMapping: FederationMapping?
    ): MutableMap<String?, Any?>? {
        val filteredMapping = federationMapping.createFilteredMapping(cidrAddress)
        val properties: MutableMap<String?, Any?> = HashMap()
        properties["cname"] = filteredMapping.cname
        properties["ttl"] = filteredMapping.ttl
        addAddressProperties("resolve4", filteredMapping.resolve4, properties)
        addAddressProperties("resolve6", filteredMapping.resolve6, properties)
        return properties
    }

    private fun addAddressProperties(
        propertyName: String?,
        cidrAddresses: ComparableTreeSet<CidrAddress?>?,
        properties: MutableMap<String?, Any?>?
    ): MutableMap<String?, Any?>? {
        val addressStrings: MutableList<String?> = ArrayList()
        if (cidrAddresses == null || cidrAddresses.isEmpty()) {
            return properties
        }
        for (cidrAddress in cidrAddresses) {
            addressStrings.add(cidrAddress.getAddressString())
        }
        properties[propertyName] = addressStrings
        return properties
    }

    fun setFederationRegistry(federationRegistry: FederationRegistry?) {
        this.federationRegistry = federationRegistry
    }
}