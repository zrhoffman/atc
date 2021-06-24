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
import com.comcast.cdn.traffic_control.traffic_router.core.util.ComparableTreeSet
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.log4j.Logger
import java.io.IOException

class FederationMappingBuilder {
    @Throws(JsonUtilsException::class, IOException::class)
    fun fromJSON(json: String?): FederationMapping? {
        val mapper = ObjectMapper()
        val jsonNode = mapper.readTree(json)
        val cname = JsonUtils.getString(jsonNode, "cname")
        val ttl = JsonUtils.getInt(jsonNode, "ttl")
        val network = ComparableTreeSet<CidrAddress?>()
        if (jsonNode.has("resolve4")) {
            val networkList = JsonUtils.getJsonNode(jsonNode, "resolve4")
            network.addAll(buildAddresses(networkList))
        }
        val network6 = ComparableTreeSet<CidrAddress?>()
        if (jsonNode.has("resolve6")) {
            val network6List = JsonUtils.getJsonNode(jsonNode, "resolve6")
            network6.addAll(buildAddresses(network6List))
        }
        return FederationMapping(cname, ttl, network, network6)
    }

    private fun buildAddresses(networkArray: JsonNode?): ComparableTreeSet<CidrAddress?>? {
        val network = ComparableTreeSet<CidrAddress?>()
        for (currNetwork in networkArray) {
            val addressString = currNetwork.asText()
            try {
                val cidrAddress: CidrAddress = CidrAddress.Companion.fromString(addressString)
                network.add(cidrAddress)
            } catch (e: NetworkNodeException) {
                FederationMappingBuilder.Companion.LOGGER.warn(e.message)
            }
        }
        return network
    }

    companion object {
        private val LOGGER = Logger.getLogger(FederationMapping::class.java)
    }
}