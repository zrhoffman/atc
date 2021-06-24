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

import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.IOException

class FederationsBuilder {
    @Throws(JsonUtilsException::class, IOException::class)
    fun fromJSON(jsonString: String?): MutableList<Federation?>? {
        val federations: MutableList<Federation?> = ArrayList()
        val mapper = ObjectMapper()
        val jsonObject = mapper.readTree(jsonString)
        val federationList = JsonUtils.getJsonNode(jsonObject, "response")
        for (currFederation in federationList) {
            val deliveryService = JsonUtils.getString(currFederation, "deliveryService")
            val mappings: MutableList<FederationMapping?> = ArrayList()
            val mappingsList = JsonUtils.getJsonNode(currFederation, "mappings")
            val federationMappingBuilder = FederationMappingBuilder()
            for (mapping in mappingsList) {
                mappings.add(federationMappingBuilder.fromJSON(mapping.toString()))
            }
            val federation = Federation(deliveryService, mappings)
            federations.add(federation)
        }
        return federations
    }
}