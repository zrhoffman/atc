/*
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

import com.comcast.cdn.traffic_control.traffic_router.core.loc.AnonymousIpWhitelist
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNode.SuperNode
import com.comcast.cdn.traffic_control.traffic_router.core.loc.NetworkNodeException
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtilsException
import com.fasterxml.jackson.databind.JsonNode
import org.apache.log4j.Logger

class AnonymousIpWhitelist {
    private val whitelist: SuperNode?

    @Throws(JsonUtilsException::class, NetworkNodeException::class)
    fun init(config: JsonNode?) {
        if (config.isArray()) {
            for (node in config) {
                val network = node.asText()
                add(network)
            }
        }
    }

    @Throws(NetworkNodeException::class)
    fun add(network: String?) {
        val node = NetworkNode(network, AnonymousIp.Companion.WHITE_LIST_LOC)
        if (network.indexOf(':') == -1) {
            whitelist.add(node)
        } else {
            whitelist.add6(node)
        }
    }

    operator fun contains(address: String?): Boolean {
        if (whitelist == null) {
            return false
        }
        try {
            val nn = whitelist.getNetwork(address)
            if (nn.loc === AnonymousIp.Companion.WHITE_LIST_LOC) {
                return true
            }
        } catch (e: NetworkNodeException) {
            AnonymousIpWhitelist.Companion.LOGGER.warn("AnonymousIp: exception", e)
        }
        return false
    }

    companion object {
        private val LOGGER = Logger.getLogger(AnonymousIpWhitelist::class.java)
    }

    init {
        whitelist = SuperNode()
    }
}