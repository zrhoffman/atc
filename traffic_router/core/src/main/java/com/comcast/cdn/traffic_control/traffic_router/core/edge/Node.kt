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

import com.comcast.cdn.traffic_control.traffic_router.core.edge.Cache.DeliveryServiceReference
import com.comcast.cdn.traffic_control.traffic_router.core.edge.Node
import com.comcast.cdn.traffic_control.traffic_router.core.hash.DefaultHashable
import com.comcast.cdn.traffic_control.traffic_router.core.util.JsonUtils
import com.fasterxml.jackson.databind.JsonNode
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder
import org.apache.log4j.Logger
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

open class Node : DefaultHashable {
    enum class IPVersions {
        IPV4ONLY, IPV6ONLY, ANY
    }

    protected val id: String?
    private var fqdn: String? = null
    private var ipAddresses: MutableList<InetRecord?>? = null
    private var ip4: InetAddress? = null
    private var ip6: InetAddress? = null
    private var isAvailable = false
    private var ipv4Available = true
    private var ipv6Available = true
    private var hasAuthority = false
    private var port = 0
    private val deliveryServices: MutableMap<String?, DeliveryServiceReference?>? = HashMap()
    private val capabilities: MutableSet<String?>? = HashSet()
    private var httpsPort = 443

    constructor(id: String?) {
        this.id = id
        generateHashes(id, Node.Companion.REPLICAS)
    }

    // alternate constructor
    constructor(id: String?, hashId: String?, hashCount: Int) {
        this.id = id
        generateHashes(hashId, if (hashCount > 0) hashCount else Node.Companion.REPLICAS)
    }

    override fun equals(obj: Any?): Boolean {
        return if (this === obj) {
            true
        } else if (obj is Node) {
            val rhs = obj as Node?
            EqualsBuilder()
                .append(getId(), rhs.getId())
                .isEquals
        } else {
            false
        }
    }

    fun getFqdn(): String? {
        return fqdn
    }

    fun getId(): String? {
        return id
    }

    fun getIpAddresses(ttls: JsonNode?): MutableList<InetRecord?>? {
        return getIpAddresses(ttls, true)
    }

    fun getIpAddresses(ttls: JsonNode?, ip6RoutingEnabled: Boolean): MutableList<InetRecord?>? {
        if (ipAddresses == null) {
            return null
        }
        val ret: MutableList<InetRecord?> = ArrayList()
        for (ir in ipAddresses) {
            if (ir.isInet6() && !ip6RoutingEnabled) {
                continue
            }
            var ttl: Long = 0
            if (ttls == null) {
                ttl = -1
            } else if (ir.isInet6()) {
                ttl = optLong(ttls, "AAAA")
            } else {
                ttl = optLong(ttls, "A")
            }
            ret.add(InetRecord(ir.getAddress(), ttl))
        }
        return ret
    }

    fun getPort(): Int {
        return port
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(1, 31)
            .append(getId())
            .toHashCode()
    }

    fun addCapabilities(capabilities: MutableSet<String?>?) {
        this.capabilities.addAll(capabilities)
    }

    fun getCapabilities(): MutableSet<String?>? {
        return capabilities
    }

    open fun setDeliveryServices(deliveryServices: MutableCollection<DeliveryServiceReference?>?) {
        for (deliveryServiceReference in deliveryServices) {
            this.deliveryServices[deliveryServiceReference.getDeliveryServiceId()] = deliveryServiceReference
        }
    }

    open fun hasDeliveryService(deliveryServiceId: String?): Boolean {
        return deliveryServices.containsKey(deliveryServiceId)
    }

    fun setFqdn(fqdn: String?) {
        this.fqdn = fqdn
    }

    fun setIpAddresses(ipAddresses: MutableList<InetRecord?>?) {
        this.ipAddresses = ipAddresses
    }

    fun setPort(port: Int) {
        this.port = port
    }

    override fun toString(): String {
        return "Node [id=$id] "
    }

    fun setIsAvailable(isAvailable: Boolean) {
        hasAuthority = true
        this.isAvailable = isAvailable
    }

    fun hasAuthority(): Boolean {
        return hasAuthority
    }

    fun isAvailable(): Boolean {
        return isAvailable
    }

    fun isAvailable(requestVersion: IPVersions?): Boolean {
        return when (requestVersion) {
            IPVersions.IPV4ONLY -> isAvailable && ipv4Available
            IPVersions.IPV6ONLY -> isAvailable && ipv6Available
            else -> isAvailable
        }
    }

    @Throws(UnknownHostException::class)
    fun setIpAddress(ip: String?, ip6: String?, ttl: Long) {
        ipAddresses = ArrayList()
        if (ip != null && !ip.isEmpty()) {
            ip4 = InetAddress.getByName(ip)
            ipAddresses.add(InetRecord(ip4, ttl))
        } else {
            Node.Companion.LOGGER.error(getFqdn() + " - no IPv4 address configured!")
        }
        if (ip6 != null && !ip6.isEmpty()) {
            val ip6addr = ip6.replace("/.*".toRegex(), "")
            this.ip6 = Inet6Address.getByName(ip6addr)
            ipAddresses.add(InetRecord(this.ip6, ttl))
        } else {
            Node.Companion.LOGGER.error(getFqdn() + " - no IPv6 address configured!")
        }
    }

    fun getIp4(): InetAddress? {
        return ip4
    }

    fun getIp6(): InetAddress? {
        return ip6
    }

    fun setState(state: JsonNode?) {
        if (state == null) {
            Node.Companion.LOGGER.warn("got null health state for $fqdn. Setting it to unavailable!")
            isAvailable = false
            ipv4Available = false
            ipv6Available = false
        } else {
            isAvailable = JsonUtils.optBoolean(state, "isAvailable", true)
            ipv4Available = JsonUtils.optBoolean(state, "ipv4Available", true)
            ipv6Available = JsonUtils.optBoolean(state, "ipv6Available", true)
        }
        setIsAvailable(isAvailable)
    }

    fun getHttpsPort(): Int {
        return httpsPort
    }

    fun setHttpsPort(httpsPort: Int) {
        this.httpsPort = httpsPort
    }

    companion object {
        private val LOGGER = Logger.getLogger(Node::class.java)
        private const val REPLICAS = 1000
    }
}