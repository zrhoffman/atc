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
package com.comcast.cdn.traffic_control.traffic_router.core.edge

import com.comcast.cdn.traffic_control.traffic_router.core.edge.Resolver
import org.apache.log4j.Logger
import java.net.Inet4Address
import java.net.UnknownHostException

open class Resolver {
    open fun resolve(fqdn: String?): MutableList<InetRecord?>? {
        var ipAddresses: MutableList<InetRecord?>? = null
        try {
            val addresses = Inet4Address.getAllByName(fqdn)
            ipAddresses = ArrayList()
            for (address in addresses) {
                if (!address.isAnyLocalAddress && !address.isLoopbackAddress && !address.isLinkLocalAddress
                    && !address.isMulticastAddress
                ) {
                    ipAddresses.add(InetRecord(address, 0))
                }
            }
            if (ipAddresses.isEmpty()) {
                Resolver.Companion.LOGGER.info(String.format("No public addresses found for: (%s)", fqdn))
                //				ipAddresses = null; // jlaue - give it a chance to recover next time?  
            }
        } catch (e: UnknownHostException) {
            Resolver.Companion.LOGGER.warn(String.format("Unable to determine IP Address for: (%s)", fqdn))
        }
        return ipAddresses
    }

    companion object {
        private val LOGGER = Logger.getLogger(Resolver::class.java)
    }
}